# Computador de 8 bits e 16 bits com Montador em Python

## Conteúdo do Repositório

* **`montador.py`**: O montador desenvolvido em Python.
* **`computador_8_bits.circ`**: Contendo o arquivo `.circ` do Logisim com o circuito do processador de 8 bits.
* **`computador_16_bits.circ`**: O circuito do processador de 16 bits (versão estendida).
  
## Visão Geral do Projeto

Este projeto aborda os princípios fundamentais da computação, desde a lógica de portas (baseada nas NAND Gates, conforme o livro But How Do It Know?) até a execução de programas em uma arquitetura de CPU simples.

### Processador de 8 bits

* **Arquitetura:** CPU de 8 bits com registradores de propósito geral (`r0`-`r3`), acumulador (`ACC`), registrador de endereço de memória (`MAR`), registrador de instrução (`IR`), e registrador de endereço de instrução (`IAR`).
* **Memória:** RAM de 256 bytes (endereços de 0x00 a 0xFF).
* **Unidade Lógica Aritmética (ALU):** Implementa operações básicas como ADD, SHR, SHL, NOT, AND, OR, XOR, CMP.
* **Controle de Fluxo:** Suporte a saltos incondicionais (`JMP`, `JMPR`) e condicionais (`JA`, `JE`, `JZ`, etc.).
* **I/O:** Instruções de entrada e saída (`IN`, `OUT`) para comunicação com periféricos, no projeto foram adicionados uma porta para entrada/saída, teclado e monitor simulados.

### Processador de 16 bits

* **Extensão:** Uma versão aprimorada do processador de 8 bits, com barramentos e registradores expandidos para 16 bits.
* **Implicações:** Aumenta a capacidade de endereçamento de memória e a precisão das operações aritméticas. 

## O Montador (`montador.py`)

O `montador.py` é uma ferramenta que traduz o código Assembly (mais legível para humanos) para o código de máquina (sequências de bytes hexadecimais) que o processador entende.

### Funcionalidades Chave:

* **Montagem de Duas Passadas:** Processa o código Assembly em duas etapas:
    1.  **Primeira Passada:** Identifica e registra todas as `labels` (rótulos de endereços) e seus respectivos endereços na memória. Isso permite o uso de saltos para `labels` definidas em qualquer parte do código.
    2.  **Segunda Passada:** Converte as instruções em seus opcodes hexadecimais, utilizando os endereços das `labels` resolvidos na primeira passada.
* **Tratamento de Instruções Padrão:** Suporta todas as instruções definidas na arquitetura (LD, ST, DATA, JMP, JMPR, condicionais, CLF, ADD, SHR, SHL, NOT, AND, OR, XOR, CMP, IN, OUT).
* **Pseudo-Instruções:** Expandem para uma ou mais instruções reais do processador, simplificando a programação Assembly:
    * `CLF reg`: Limpa o conteúdo de um registrador (implementado com `XOR reg, reg`).
    * `Move reg_dest, reg_src`: Copia o conteúdo de um registrador para outro (implementado com `XOR reg_dest, reg_dest` seguido de `ADD reg_dest, reg_src`).
    * `HALT`: Para a execução do programa (implementado com `JMP .` - salto para a própria instrução).
* **Processamento de Dados:** Aceita números em decimal, hexadecimal (`0x`), e binário (`0b`).
* **Validação de Escala:** Verifica se os valores imediatos e endereços estão dentro do intervalo permitido (ex: `-128` a `255` para `DATA` e `0` a `255` para endereços).
* **Formato de Saída:** Gera um arquivo `.m` (de memória) no formato `v3.0 hex words plain`, com cada byte em uma nova linha, compatível com o Logisim.

