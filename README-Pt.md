# WhatInjector

<img src=img/8bit.gif/>

*WhatInjector é um projeto que eu fiz com alguns truques e técnicas legais para contornar AVs e, talvez, até alguns EDRs*

**Técnicas**  
* **Funções NTAPI**</br>
  *Funções NTAPI são funções internas que fazem parte do ntdll.dll e são pouco documentadas no Windows. As funções que são comuns da WINAPI, como VirtualAlloc, ReadFile e OpenProcess, são apenas wrappers que preparam os parâmetros para chamar essas funções NTAPI.*</br>
  *https://www.rotta.rocks/offensive-tool-development/evading-edr/wrapping-ntapi-functions*</br>
  *https://www.crow.rip/nest/mal/dev/inject/ntapi-injection/complete-ntapi-implementation*</br>
* **Técnica HalosGate**</br>
  *HalosGate é uma evolução da técnica HellsGate, criada pra recuperar números de syscall (SSNs) mesmo quando um EDR intercepta certas funções. Ela itera sobre as tabelas de exportação procurando a função alvo; uma vez encontrada, verifica os primeiros bytes para ver se o EDR está fazendo hook. Se estiver, tenta deshookar; caso contrário, recupera o SSN e retorna.*</br>
  *https://github.com/boku7/AsmHalosGate*</br>
  *https://redops.at/en/blog/exploring-hells-gate*</br>
* **Syscalls Indiretas**</br>
  *Syscalls indiretas também são uma evolução de uma técnica conhecida como Direct Syscalls. Essa surgiu para resolver o problema das Direct Syscalls: ao usar Direct Syscalls, o programa chamava a função diretamente via syscall. Como isso é incomum para um programa legítimo, EDRs/AVs detectam e geram um IOC toda vez que um programa executa um syscall diretamente. Por isso surgiram as Syscalls Indiretas — uma técnica que prepara os parâmetros no programa, mas executa o syscall através da função no ntdll.*</br>
  *https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls*</br>
  *https://d01a.github.io/syscalls/*</br>
* **Vectored Exception Handling**</br>
  *Como descrito anteriormente em um repositório anterior, é uma extensão do SEH (Structured Exception Handling) responsável por lidar com exceções de um programa. Permite que os programas gerenciem exceções específicas, e este injector a utiliza para executar o shellcode.*</br>
  *https://github.com/zack0x5/VEH-Shellcode-Execution*</br>
  *https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling*</br>

⚠️ **Aviso** ⚠️
---
Quero deixar claro que o conteúdo compartilhado aqui é apenas para **fins educacionais**. Não é recomendado usar este exemplo para cometer qualquer infração.
