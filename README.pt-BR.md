# Siren — Phantom Section Loader

> Uma implementação limpa e open-source de injeção de DLL baseada em seções para Windows x64.
> CET-ready. Sem admin. Sem WriteProcessMemory. Fire-and-forget.

**Autor:** Rafael Dornelas  
**Licença:** MIT

---

## Visão Geral

**Siren** implementa uma técnica chamada **Phantom Section Loader** — um método de injeção de DLL in-memory que combina mapeamento de seções pagefile-backed com um PE loader reflexivo.

O payload é entregue através de um objeto de seção NT compartilhado (sem `WriteProcessMemory`, sem `VirtualAllocEx`), e a execução é disparada via `NtCreateThreadEx`. O injetor pode fechar todos os handles e sair imediatamente — o payload roda de forma independente dentro do processo alvo.

### Propriedades

| Propriedade | Descrição |
|---|---|
| **CET-Ready** | Todos os alvos de chamadas indiretas começam com `endbr64`. Preparado para futura aplicação de IBT no Windows. |
| **Zero WriteProcessMemory** | Payload entregue via `NtCreateSection` + `NtMapViewOfSection` (seção compartilhada). |
| **Zero VirtualAllocEx** | Memória no alvo alocada pelo gerenciador de memória NT via mapeamento de seção. |
| **Sem Admin / Sem UAC** | Funciona como usuário padrão. Sem necessidade de `SeDebugPrivilege`. |
| **Fire-and-Forget** | Injetor sai imediatamente após a injeção. Payload roda independente. |
| **Imports Seguros contra Forwarders** | Usa `GetProcAddress` para resolução da IAT, lidando corretamente com API forwarders (ex: `CreateFileW → KERNELBASE`). |

---

## Prior Art e Contribuição

O Siren se baseia em técnicas bem estabelecidas da comunidade de pesquisa em segurança:

| Componente | Prior Art |
|---|---|
| Mapeamento de seção sem WPM | [Barakat, 2018](https://gist.github.com/Barakat/1dccd8e5336c660b18eeda46b86113ce); [SafeBreach / Pinjectra, Black Hat 2019](https://github.com/SafeBreach-Labs/pinjectra) |
| Injeção reflexiva de DLL | [Stephen Fewer, 2008](https://github.com/stephenfewer/ReflectiveDLLInjection) |
| Entrega por seção + PE loading manual | [Hunt & Hackett, 2022](https://www.huntandhackett.com/blog/concealed-code-execution-techniques-and-detection) |
| PEB walk + NtCreateThreadEx | Documentado extensivamente desde ~2017 |

### O que o Siren contribui

1. **Implementação de referência open-source** — Uma biblioteca C limpa e bem documentada integrando injeção por seção + PE loader reflexivo com uma API simples `siren_inject()`.
2. **Tratamento de API forwarders** — Documenta e resolve o problema de forwarders (ex: `kernel32!CreateFileW` → `KERNELBASE!CreateFileW`) que quebra o export table walking manual em loaders reflexivos. Solução: resolver apenas `GetProcAddress` manualmente, usar ele para todo o resto.
3. **Shellcode CET-ready** — `endbr64` em todos os alvos de chamadas indiretas. Nota: o Windows atualmente aplica Shadow Stack + CFG, não IBT. Esta é uma preparação para o futuro, não um bypass de uma mitigação ativa.

> **Nota de honestidade:** As técnicas centrais (mapeamento de seção, carregamento reflexivo, NtCreateThreadEx) são individualmente bem conhecidas. O valor do Siren está na integração, documentação e na correção de forwarders — não em reivindicar um método "novo" de injeção.

---

## Técnica

```
INJETOR                                    ALVO (processo filho)
───────                                    ─────────────────────
1. CreateProcess(SUSPENDED)         ──→    Criado, apenas ntdll.dll carregada

2. NtCreateSection(RWX, pagefile)
   NtMapViewOfSection(self, RW)
   Escreve [stub PIC | payload PE]
   NtUnmapViewOfSection(self)
   NtMapViewOfSection(alvo, RWX)    ──→    Seção compartilhada mapeada

3. ResumeThread()                   ──→    Processo inicializa (kernel32 carregada)

4. NtCreateThreadEx(SirenStubEntry) ──→    Stub PIC executa:
   Fecha handles, SAIR                      • PEB walk → encontra kernel32.dll
                                             • Export walk manual → GetProcAddress
                                             • Carregamento reflexivo do PE
                                             • Chama DllMain(DLL_PROCESS_ATTACH)
```

---

## Comparação

| Recurso | Injeção Clássica | Reflective DLL Injection | **Siren** |
|---|---|---|---|
| WriteProcessMemory | ✅ Necessário | ✅ Necessário | ❌ Não usado |
| VirtualAllocEx | ✅ Necessário | ✅ Necessário | ❌ Não usado |
| LoadLibrary | ✅ Necessário | ❌ Não usado | ❌ Não usado |
| Admin necessário | Às vezes | Geralmente | **Nunca** |
| API forwarders | ✅ Funciona (SO) | ❌ Frequentemente quebra | **✅ Funciona** |
| Fire-and-forget | ❌ Não | ❌ Não | **✅ Sim** |

---

## Build

### Requisitos

- CMake 3.20+
- Compilador cruzado MinGW-w64 (GCC com assembler GAS)
- Python 3 (para encriptação do stub em tempo de configuração)
- Host Linux (compilação cruzada para Windows x64)

### Compilar

```bash
cd Siren
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/mingw64.cmake
cmake --build .
```

Na configuração, `cmake/gen_stub.py` lê `cmake/stub_x64.bin`, encripta com uma chave
XOR aleatória de 16 bytes e gera `sr_stub_gen.h` no diretório de build — cada build
produz um blob encriptado único.

Saída:
- `siren_injector.exe` — injetor standalone

---

## Uso

No Windows (sem admin):

```powershell
.\siren_injector.exe .\payload.dll
```

O injetor cria um processo filho `cmd.exe` suspenso, mapeia o payload via seção NT
compartilhada (sem `WriteProcessMemory`), e inicia o stub PIC via `NtCreateThreadEx`.
O injetor sai imediatamente; o payload roda de forma independente.

---

## Estrutura do Projeto

```
Siren/
├── src/
│   ├── siren.c                  # Injetor + pipeline completo de injeção
│   ├── siren.h                  # API pública (siren_inject)
│   ├── siren_stub_x64.S         # Loader reflexivo PIC (x64 GAS assembly, 539 linhas)
│   ├── siren_injector.manifest  # Manifesto Windows (UAC, DPI)
│   └── siren_injector.rc        # Resource file Windows (informações de versão)
├── cmake/
│   ├── gen_stub.py              # Encripta stub → sr_stub_gen.h (executado na configuração)
│   ├── stub_x64.bin             # Blob do stub PIC pré-compilado
│   ├── options.cmake            # Flags e opções de build
│   ├── version.cmake            # Constantes de versão
│   ├── modules/                 # Módulos CMake utilitários (DetectArch, HardenFlags)
│   └── toolchains/              # Arquivos de toolchain para compilação cruzada
├── doc/
│   ├── TECHNIQUE.md             # Deep-dive técnico (EN)
│   └── TECHNIQUE.pt-BR.md      # Deep-dive técnico (PT-BR)
├── CMakeLists.txt
├── README.md                    # EN
└── README.pt-BR.md             # Este arquivo (PT-BR)
```

---

## Licença

MIT — veja [LICENSE](LICENSE).

## Autor

**Rafael Dornelas** — [rafaelwdornelasstl@gmail.com](mailto:rafaelwdornelasstl@gmail.com)
