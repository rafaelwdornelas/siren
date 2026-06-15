# Siren — Phantom Section Loader: Análise Técnica Detalhada

**Autor:** Rafael Dornelas  
**Técnica:** NtCreateSection + NtMapViewOfSection + NtCreateThreadEx  
**SO Alvo:** Windows 10/11 x64 (incluindo 24H2 com CET-IBT)

---

## Índice

1. [Prior Art e Contribuição](#prior-art-e-contribuição)
2. [Problema](#problema)
3. [Visão Geral da Solução](#visão-geral-da-solução)
4. [CET-IBT: Preparação para o Futuro](#cet-ibt-preparação-para-o-futuro)
5. [Pipeline de Injeção](#pipeline-de-injeção)
6. [Layout de Memória](#layout-de-memória)
7. [Arquitetura do Stub PIC](#arquitetura-do-stub-pic)
8. [Mapeamento de Seção vs WriteProcessMemory](#mapeamento-de-seção-vs-writeprocessmemory)
9. [GetProcAddress vs Export Walking Manual](#getprocaddress-vs-export-walking-manual)
10. [Decisões de Design](#decisões-de-design)
11. [Comparação com Técnicas Existentes](#comparação-com-técnicas-existentes)

---

## Prior Art e Contribuição

O Siren se baseia em técnicas bem estabelecidas. Créditos:

| Componente | Prior Art |
|---|---|
| Mapeamento de seção sem WPM | [Barakat, 2018](https://gist.github.com/Barakat/1dccd8e5336c660b18eeda46b86113ce); [SafeBreach / Pinjectra, Black Hat 2019](https://github.com/SafeBreach-Labs/pinjectra) |
| Injeção reflexiva de DLL | [Stephen Fewer, 2008](https://github.com/stephenfewer/ReflectiveDLLInjection) |
| Entrega por seção + PE loading manual | [Hunt & Hackett, 2022](https://www.huntandhackett.com/blog/concealed-code-execution-techniques-and-detection) |
| PEB walk + NtCreateThreadEx | Documentado extensivamente desde ~2017 |

**O que o Siren contribui:**

1. **Implementação de referência open-source** — Biblioteca C limpa integrando injeção por seção + PE loader reflexivo com uma API simples `siren_inject()`.
2. **Correção de API forwarders** — Documenta o problema de forwarders (ex: `kernel32!CreateFileW → KERNELBASE!CreateFileW`) e resolve resolvendo apenas `GetProcAddress` manualmente, usando ele para todos os outros imports.
3. **Shellcode CET-ready** — `endbr64` em todos os alvos de chamadas indiretas. Nota: o Windows atualmente aplica Shadow Stack + CFG, não IBT. Esta é uma preparação para o futuro.

---

## Problema

As técnicas existentes de injeção de DLL falham em sistemas Windows 11 modernos por três razões:

### 1. Intel CET (Control-flow Enforcement Technology)

O Intel CET tem dois componentes: **Shadow Stack** (validação de endereços de retorno) e **Indirect Branch Tracking / IBT** (exige `endbr64` em alvos de chamadas indiretas). O Windows atualmente aplica Shadow Stack + CFG (Control Flow Guard), mas **ainda não aplica IBT** em processos user-mode.

Porém, o Siren inclui `endbr64` em todos os alvos de chamadas indiretas como preparação para o futuro. Se a Microsoft habilitar a aplicação de IBT em versões futuras do Windows, o Siren funcionará sem modificação.

### 2. Mitigações do CreateRemoteThread

O `CreateRemoteThread` passa pelo `kernel32!CreateRemoteThreadEx`, que aplica políticas de mitigação de processo. No Windows 11, muitos processos têm `ProcessMitigationPolicy` configurado para bloquear a criação de threads remotas no nível da API, retornando `ERROR_ACCESS_DENIED (5)`.

### 3. Resolução de API Forwarders

As DLLs do Windows usam extensivamente **API forwarders**. Por exemplo, `kernel32.CreateFileW` redireciona para `KERNELBASE.CreateFileW`. O export table walking manual (usado por todos os loaders reflexivos conhecidos) retorna a string do forwarder em vez do endereço da função, resultando em entradas NULL na IAT e crashes na primeira chamada de API Win32.

---

## Visão Geral da Solução

O Siren resolve todos os três problemas com uma técnica chamada **Phantom Section Loader**:

| Problema | Solução |
|---|---|
| CET-IBT | `endbr64` em todos os alvos de chamadas indiretas; payload compilado com `-fcf-protection=branch` |
| CreateRemoteThread bloqueado | Usa `NtCreateThreadEx` (nível ntdll, contorna verificações de mitigação do kernel32) |
| API forwarders | Usa `GetProcAddress` do kernel32 para resolução de imports (lida com forwarders automaticamente) |
| Detecção de WriteProcessMemory | Entrega payload via `NtCreateSection` + `NtMapViewOfSection` (seção compartilhada) |
| Requisito de Admin/UAC | Alvo é um processo filho (acesso total ao handle sem privilégios) |

---

## CET-IBT: Preparação para o Futuro

### O que é CET?

> **Nota importante:** O Windows atualmente aplica **Shadow Stack + CFG**, não IBT. As instruções `endbr64` no Siren são preparação para o futuro, não um bypass de uma mitigação ativa.

O Intel **Control-flow Enforcement Technology (CET)** tem dois componentes:

- **Shadow Stack (SS):** Validação de endereços de retorno com suporte em hardware. A CPU mantém uma shadow stack separada que registra endereços de retorno. Instruções `ret` verificam se o endereço de retorno corresponde à entrada da shadow stack.

- **Indirect Branch Tracking (IBT):** Todo `call` ou `jmp` indireto deve atingir uma instrução `endbr64`. Se o alvo não começar com `endbr64`, a CPU dispara `#CP`.

### Impacto na Injeção (Quando IBT For Aplicado)

Se/quando o Windows habilitar a aplicação de IBT, qualquer shellcode injetado via `NtCreateThreadEx`, APC ou thread hijacking precisará de `endbr64` em seu ponto de entrada. O Siren já está preparado para este cenário.

### Solução do Siren

```asm
SirenStubEntry:
    endbr64                    ; ← CET-IBT: primeira instrução na entrada
    lea     r10, .Lstub_fired[rip]
    mov     eax, 1
    lock xchg dword ptr [r10], eax
    ...
```

O stub PIC coloca `endbr64` (`F3 0F 1E FA`) como a primeira instrução em `SirenStubEntry`. A DLL payload é compilada com `-fcf-protection=branch`, que insere `endbr64` em `DllMain` e todos os outros pontos de entrada de funções.

---

## Pipeline de Injeção

### Passo 1: Criar Processo Host Suspenso

```c
CreateProcessW(NULL, L"cmd.exe /c ping -n 60 127.0.0.1 >nul",
               ..., CREATE_SUSPENDED | CREATE_NO_WINDOW, ...);
```

O injetor cria um processo filho em estado suspenso. Como pai, temos acesso total ao handle (`PROCESS_ALL_ACCESS`) sem precisar de `SeDebugPrivilege` ou elevação admin.

### Passo 2: Criar e Mapear Seção

```c
// Criar seção pagefile-backed
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &size,
                PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

// Mapear localmente (RW) para escrever conteúdo
NtMapViewOfSection(hSection, GetCurrentProcess(), &local_view, ...);
siren_stub_write_to(local_view, ...);  // Escreve [stub PIC | payload PE]
NtUnmapViewOfSection(GetCurrentProcess(), local_view);

// Mapear no alvo (RWX)
NtMapViewOfSection(hSection, hProcess, &target_base, ...);
NtClose(hSection);
```

Uma única seção pagefile-backed é criada com `SEC_COMMIT`. É mapeada no espaço de endereçamento do injetor como RW para escrever o conteúdo, depois desmapeada e mapeada no alvo como RWX. O handle da seção é fechado — o mapeamento persiste enquanto o processo alvo existir.

**Insight chave:** Nenhum `WriteProcessMemory` é chamado. A seção compartilhada É o canal de escrita.

### Passo 3: Resumir e Aguardar

```c
ResumeThread(pi.hThread);
Sleep(2000);  // Aguardar kernel32.dll ser carregada
```

O processo suspenso retoma e passa pelo `LdrInitializeThunk`, que carrega `ntdll.dll → kernel32.dll → kernelbase.dll`. Após ~100ms, a `InMemoryOrderModuleList` do PEB está totalmente populada.

### Passo 4: Executar via NtCreateThreadEx

```c
void *entry = (char *)target_base + siren_stub_entry_offset();
NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                 entry, NULL, 0, 0, 0, 0, NULL);
WaitForSingleObject(hThread, 10000);
```

`NtCreateThreadEx` cria uma thread no alvo que começa a executar em `SirenStubEntry` na seção mapeada. Diferente do `CreateRemoteThread`, esta é uma syscall direta do ntdll que contorna as verificações de mitigação do kernel32.

### Passo 5: Fire-and-Forget

O injetor fecha todos os handles e sai. O payload continua rodando dentro do processo alvo de forma independente.

---

## Layout de Memória

```
Espaço de Endereçamento Virtual do Processo Alvo
─────────────────────────────────────────────────

    ┌─────────────────────────────────────┐
    │       Seção Mapeada (RWX)           │  ← NtMapViewOfSection
    │                                     │
    │  ┌──────────────────────────────┐   │
    │  │  Stub PIC (siren_stub_code)  │   │  offset 0x000
    │  │                              │   │
    │  │  SirenStubEntry:             │   │  ← NtCreateThreadEx start
    │  │    endbr64                   │   │
    │  │    [flag atômico fired]      │   │
    │  │    [PEB walk → kernel32]     │   │
    │  │    [export walk → GPA]       │   │
    │  │    [resolver APIs]           │   │
    │  │    [lógica de carga PE]      │   │
    │  │    [call DllMain]            │   │
    │  │    ret                       │   │
    │  │                              │   │
    │  │  .Lstub_fired:    .long 0    │   │  guarda atômico
    │  │  .Lstub_payload_offset: ...  │   │  patchado pelo carrier
    │  │  "GetProcAddress\0"          │   │  strings embutidas
    │  │  "VirtualAlloc\0"            │   │
    │  │  "LoadLibraryA\0"            │   │
    │  │  "FlushInstructionCache\0"   │   │
    │  └──────────────────────────────┘   │
    │  [padding até fronteira de 4 KB]    │
    │  ┌──────────────────────────────┐   │
    │  │  Payload PE (bytes brutos)   │   │  offset = blob_size (4KB-alinhado)
    │  │                              │   │
    │  │  Cabeçalho MZ                │   │
    │  │  Cabeçalhos PE               │   │
    │  │  Seção .text                 │   │
    │  │  Seção .rdata                │   │
    │  │  Seção .data                 │   │
    │  │  ...                         │   │
    │  └──────────────────────────────┘   │
    └─────────────────────────────────────┘

    ┌─────────────────────────────────────┐
    │  Imagem VirtualAlloc (RWX)          │  ← alocada pelo stub em runtime
    │                                     │
    │  PE carregado na base preferida     │
    │  Seções copiadas                    │
    │  Relocações aplicadas               │
    │  Imports resolvidos (GetProcAddress) │
    │  DllMain chamada                    │
    └─────────────────────────────────────┘
```

---

## Arquitetura do Stub PIC

O stub PIC (Position-Independent Code) é o núcleo do Siren. É um blob de shellcode x64 autocontido que:

### 1. Encontra kernel32.dll via PEB Walk

```asm
mov     rax, gs:[0x60]          ; PEB
mov     rax, [rax + 0x18]       ; PEB->Ldr
lea     rdi, [rax + 0x20]       ; &InMemoryOrderModuleList
mov     rax, [rdi]              ; 1ª entrada (exe)
mov     rax, [rax]              ; 2ª entrada (ntdll)
mov     rax, [rax]              ; 3ª entrada (kernel32)
mov     r12, [rax + 0x20]       ; DllBase
```

A `InMemoryOrderModuleList` no PEB sempre tem kernel32.dll como a 3ª entrada no Windows 10/11 x64.

### 2. Resolve GetProcAddress (Export Walk Manual)

Apenas `GetProcAddress` é resolvido manualmente percorrendo o diretório de exportação do kernel32. Este é um custo único — toda resolução subsequente de API passa pelo `GetProcAddress`.

### 3. Resolve APIs Restantes

```asm
; VirtualAlloc, FlushInstructionCache, LoadLibraryA
mov     rcx, r12                ; base do kernel32
lea     rdx, .Lstr_VirtualAlloc[rip]
call    rbx                     ; GetProcAddress
```

### 4. Carregamento Reflexivo do PE

O stub realiza um carregamento manual completo do PE:
- **Cabeçalhos:** Copia `SizeOfHeaders` bytes
- **Seções:** Copia cada seção para seu `VirtualAddress`
- **Relocações:** Processa entradas `IMAGE_REL_BASED_DIR64` (soma delta aos QWORDs)
- **Imports:** Percorre `IMAGE_IMPORT_DESCRIPTOR`, chama `LoadLibraryA` + `GetProcAddress` para cada função

### 5. Chama DllMain

```asm
mov     eax, [r13 + 0x28]      ; AddressOfEntryPoint
lea     rax, [r14 + rax]       ; endereço absoluto do DllMain
mov     rcx, r14               ; hinstDLL
mov     edx, 1                 ; DLL_PROCESS_ATTACH
xor     r8, r8                 ; lpvReserved = NULL
call    rax                    ; CET-safe (DllMain tem endbr64)
```

---

## Mapeamento de Seção vs WriteProcessMemory

| Aspecto | WriteProcessMemory | Mapeamento de Seção |
|---|---|---|
| Chamada de API | `kernel32!WriteProcessMemory` | `ntdll!NtMapViewOfSection` |
| Superfície de detecção | Hookado por EDR/AV, logado pelo ETW | Nível mais baixo, menos hooks |
| Origem da memória | Heap do injetor → memória alocada do alvo | Seção pagefile compartilhada |
| Permissões necessárias | `PROCESS_VM_WRITE` + `PROCESS_VM_OPERATION` | Apenas `PROCESS_VM_OPERATION` |
| Alocação | Requer `VirtualAllocEx` separado | O mapeamento de seção É a alocação |
| Limpeza | Deve liberar explicitamente em caso de falha | Seção liberada automaticamente quando o mapeamento é removido |

---

## GetProcAddress vs Export Walking Manual

Loaders reflexivos tradicionais percorrem a tabela de exportação manualmente para resolver funções de API. Isso quebra em **API forwarders**.

### O Problema dos Forwarders

```
Tabela de exportação kernel32.dll:
  CreateFileW → "api-ms-win-core-file-l1-1-0.CreateFileW"
                 (string de forwarder, NÃO um endereço de função)
```

Um export walker manual retorna o ponteiro da string do forwarder em vez do endereço real da função. O loader reflexivo escreve esse ponteiro de string na IAT, e a primeira chamada a `CreateFileW` salta para uma string — crash instantâneo.

### Solução do Siren

O Siren resolve `GetProcAddress` uma única vez (manualmente, da tabela de exportação do kernel32 — `GetProcAddress` em si NÃO é um forwarder), depois usa ele para todo o resto:

```asm
; Para cada função importada:
mov     rcx, r8                ; hModule (DLL carregada)
mov     rdx, [import_name]     ; nome da função
call    [rbp - 0x58]           ; GetProcAddress — lida com forwarders!
mov     [r10], rax             ; escreve na IAT
```

`GetProcAddress` internamente segue a cadeia de forwarders e retorna o endereço real da função na DLL alvo (ex: `KERNELBASE.CreateFileW`).

---

## Decisões de Design

### Por que cmd.exe como processo host?

No Windows 11, `notepad.exe` é um wrapper UWP que cria um processo filho e sai. O PID pai se torna inválido antes que `NtCreateThreadEx` possa ser chamado. `cmd.exe` é um processo Win32 clássico que permanece vivo de forma confiável.

### Por que Sleep(2000) em vez de WaitForInputIdle?

`WaitForInputIdle` só funciona com processos GUI que têm um message loop. Aplicativos de console como `cmd.exe` fazem ele retornar imediatamente com `WAIT_FAILED`. Um sleep de 2 segundos é mais que suficiente para o NT loader inicializar kernel32.dll (~100ms na prática).

### Por que NtCreateThreadEx em vez de CreateRemoteThread?

`CreateRemoteThread` passa pelo `kernel32!CreateRemoteThreadEx`, que verifica políticas de mitigação de processo. Processos protegidos no Windows 11 bloqueiam isso no nível da API. `NtCreateThreadEx` é a syscall subjacente do ntdll e contorna essas verificações.

### Por que um flag atômico fired?

O stub inclui um guarda atômico `lock xchg` para prevenir execução dupla. Em cenários onde múltiplos mecanismos de trigger são armados, o flag garante que o loader reflexivo rode exatamente uma vez.

---

## Comparação com Técnicas Existentes

| Técnica | Entrega | Trigger | CET | Admin | Forwarders |
|---|---|---|---|---|---|
| CreateRemoteThread + LoadLibrary | WPM | CRT | N/A | Às vezes | ✅ (SO lida) |
| APC Injection | WPM | QueueUserAPC | ❌ | Às vezes | Depende |
| Thread Hijacking (SetThreadContext) | WPM | Redirect RIP | ❌ | Sim | Depende |
| Reflective DLL Injection | WPM | CRT/APC | ❌ | Geralmente | ❌ Quebra |
| Process Hollowing | WPM | SetThreadContext | ❌ | Às vezes | N/A |
| **Siren (Phantom Section Loader)** | **Seção** | **NtCreateThreadEx** | **✅** | **Não** | **✅** |

---

## Referências

- [Especificação Intel CET](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html)
- [Windows Internals, 7ª Edição](https://docs.microsoft.com/en-us/sysinternals/) — Estrutura PEB, dados LDR
- [Código Fonte ReactOS](https://reactos.org/) — Documentação de APIs NT
- [MSDN: NtCreateSection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatesection)
