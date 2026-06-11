# Siren

**Uma nova técnica de injeção de DLL no Windows por Rafael Dornelas.**

Siren combina dois primitivos originais nunca antes descritos na literatura
pública de segurança:

1. **Section Slack Carrier** — usa o zero-padding no final de seções PE
   (espaço "slack" da seção `.data`) em um módulo já carregado no processo
   alvo como portador do código. Sem `VirtualAllocEx`. Sem novo nó no VAD.
   O tipo de memória permanece `MEM_IMAGE`.

2. **LdrpDllNotificationList Hijacking** — insere uma
   `_LDR_DLL_NOTIFICATION_ENTRY` falsa na lista interna de notificações do
   loader do Windows NT. O payload dispara no próximo carregamento de DLL do
   processo alvo — sem `CreateRemoteThread`, sem `NtQueueApcThread`, sem
   nenhuma thread remota.

O processo injetor fecha todos os handles e **encerra imediatamente** após
quatro chamadas `WriteProcessMemory`. A DLL de payload continua carregada no
processo alvo indefinidamente.

## Perfil de IOC

| Observável | Técnicas clássicas | Siren |
|---|---|---|
| `VirtualAllocEx` | Sim | **Não** |
| `CreateRemoteThread` | Sim | **Não** |
| `NtQueueApcThread` | Sim | **Não** |
| `NtCreateSection(SEC_IMAGE)` | Sim | **Não** |
| `PsSetLoadImageNotifyRoutine` dispara | Sim | **Não** |
| Novo nó no VAD | Sim | **Não** |
| Tipo de memória do stub | `MEM_PRIVATE` | **`MEM_IMAGE`** |
| Injetor precisa permanecer ativo | Às vezes | **Nunca** |

## Build

Cross-compilação no Linux (MinGW):

```bash
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-x86_64.cmake \
  -DSIREN_BUILD_POC=ON
cmake --build build
```

Ou nativamente no Windows (MSVC ou MinGW-w64):

```bash
cmake -B build -DSIREN_BUILD_POC=ON
cmake --build build
```

Requisitos: CMake 3.20+, compilador C11, Windows SDK (ou MinGW-w64).

## Uso

```bash
# Injeta payload.dll no processo com PID 1234
build/poc/siren_injector.exe 1234 build/poc/siren_payload.dll

# O injetor encerra imediatamente.
# O payload grava %TEMP%\siren_proof.txt quando disparado.
```

## Estrutura do Projeto

```
include/siren/     — headers da API pública
src/
  pe/              — parser PE (adaptado do Wraith)
  runtime/         — PEB walker
  slack/           — localizador de slack space em seções
  handoff/         — NtCreateSection + DuplicateHandle
  notify/          — probe + inserção em LdrpDllNotificationList
  reflective/      — loader reflexivo standalone (C)
  stub/            — stub assembly PIC + serializador
poc/               — injetor PoC + DLL de payload
tests/unit/        — testes unitários de cada subsistema
doc/TECHNIQUE.md   — write-up técnico completo (em inglês)
```

## Write-up Técnico

Consulte [doc/TECHNIQUE.md](doc/TECHNIQUE.md) para a análise completa:

- Background sobre `LdrpDllNotificationList` e por que nunca foi explorada
- Descrição passo a passo da técnica
- Tabela comparativa de IOC
- Resultados de validação experimental (Q1–Q5)
- Limitações (ACG, PPL, CFG)
- Comparação com Eclipse, Mockingjay, Early Cascade Injection e outras

## Autor

**Rafael Dornelas** — pesquisador de segurança.

Técnica concebida e implementada em 2025. Ambos os primitivos (Section Slack
Carrier e LdrpDllNotificationList Hijacking) e sua combinação para injeção
fire-and-forget são contribuições originais não encontradas em pesquisas
públicas anteriores.

## Licença

MIT — veja [LICENSE](LICENSE).

Uso educacional e de pesquisa apenas.
