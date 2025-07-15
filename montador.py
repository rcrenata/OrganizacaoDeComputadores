

import sys
import re

# Mapeamento de Opcodes e Registradores
# O dicionário mapeia cada instrução assembly para sua representação binária ou hexadecimal direta
OPCODES = {
    # Instruções de 1 ou 2 bytes. O formato do Byte 1 é OPCODE(4 bits) + Bits de operandos,
    # a não ser que seja um OPCODE de 8 bits completo. O segundo byte, se houver, é o valor/endereço

    # Instruções de manipulação de registradores (LD, ST):
    # Byte 1: OPCODE(4 bits) | R_DEST(2 bits) | R_SRC(2 bits)
    "ld": "0000",
    "st": "0001",

    # Instrução DATA:
    # A regra para o primeiro byte de DATA é agora mapeada diretamente para CADA REGISTRADOR
    # para corresponder EXATAMENTE à "saída certa" fornecida pelo usuário, que tem um padrão particular.
    # Ex: r0 -> 20, r1 -> 21, r2 -> 22, r3 -> 23.
    # (Note que isso difere de uma regra simples como "0010_RR_00" para todos os Rs)
    "data_r0": "20", # Para data r0, X
    "data_r1": "21", # Para data r1, X
    "data_r2": "22", # Para data r2, X
    "data_r3": "23", # Para data r3, X
    "data": "0010", # Mantido para opcode base, mas será usado de forma diferente

    # Instrução JMPR (Jump Register):
    # Byte 1: OPCODE(4 bits: "0011") | PADDING('00') (2 bits) | R_SRC(2 bits)
    "jmpr": "0011",

    # Jumps Incondicionais e Condicionais:
    # Para estas instruções, o OPCODES armazena diretamente o valor HEX de 8 bits para o Byte 1,
    # conforme mostrado na coluna "BYTE 1 (HEX)" da planilha de instruções em 8 bits
    # O Byte 2 sempre será o endereço de 8 bits
    "jmp": "40",
    "jc": "58",
    "ja": "54",
    "je": "52",
    "jz": "51",
    "jca": "5C",
    "jce": "5A",
    "jcz": "59",
    "jcae": "5E",
    "jcaz": "5D",
    "jcez": "57",
    "jcaez": "5F",
    "jaz": "55",
    "jaez": "5B",
    "jez": "53",
    "jae": "56",

    # Instruções de 1 byte (O OPCODE já é o byte binário completo de 8 bits ou se combina com registradores):
    # CLF é um opcode fixo de 8 bits
    "clf": "01100000", # Equivalente a 60h

    # Instruções Aritméticas e Lógicas:
    # Byte 1: OPCODE(4 bits) | R_DEST(2 bits) | R_SRC(2 bits)
    "add": "1000",
    "shr": "1001",
    "shl": "1010",
    "not": "1011",
    "and": "1100",
    "or":  "1101",
    "xor": "1110",
    "cmp": "1111",

    # Instruções de I/O:
    # Byte 1: OPCODE(4 bits: "0111") | TIPO_PORTA(2 bits) | REG(2 bits)
    # Os bits da porta (00 para data IN, 01 para addr IN, 10 para data OUT, 11 para addr OUT)
    # são combinados com os bits do registrador e o opcode base
    "in": "0111",
    "out": "0111",
}

# Mapeamento de registradores para seus 2 bits binários correspondentes
REGISTERS = {
    "r0": "00",
    "r1": "01",
    "r2": "10",
    "r3": "11"
}

# Funções Auxiliares
def parse_number(num_str):
    """
    Converte uma string que representa um número para seu valor inteiro.
    Aceita formatos: decimal, hexadecimal, e binário.
    Lida com números negativos para o formato decimal.
    """
    num_str = num_str.strip() # Remove espaços em branco
    if num_str.lower().startswith("0x"): # Verifica se é hexadecimal
        return int(num_str[2:], 16) # Converte de base 16
    elif num_str.lower().startswith("0b"): # Verifica se é binário
        return int(num_str[2:], 2) # Converte de base 2
    else: # Assume que é decimal
        try:
            return int(num_str) # Converte para inteiro decimal
        except ValueError:
            # Erro se a string não puder ser convertida para um número válido
            raise ValueError(f"Formato de número inválido: {num_str}")

def convert_to_hex(binary_string):
    """
    Converte uma string binária de 8 bits para uma string hexadecimal de 2 caracteres.
    Garanta que a string binária de entrada tenha exatamente 8 bits.
    """
    if len(binary_string) != 8:
        # Notifica um erro se o comprimento não for 8 bits, o que indica um problema na geração do opcode
        raise ValueError(f"Erro de conversão: string binária tem {len(binary_string)} bits, esperado 8.")
    # Converte a string binária para um inteiro, depois formata como hexadecimal de 2 dígitos e preenche com com '0' se necessário
    return f"{int(binary_string, 2):02x}"

def pad_binary(binary_str, length):
    """
    Preenche uma string binária com zeros à esquerda até atingir o tamanho/length.
    Usado para garantir que valores como endereços e dados imediatos tenham o número correto de bits.
    """
    return binary_str.zfill(length)

# Pré-processamento do Arquivo Assembly
def preprocess_assembly(assembly_file):
    """
    Lê o arquivo assembly, linha por linha
    Remove comentários, converte o texto para minúsculas e tokeniza cada linha em uma lista de palavras
    Retorna uma lista de listas (cada sublista é uma linha tokenizada)
    """
    processed_lines = [] # Lista para armazenar as linhas processadas
    with open(assembly_file, 'r') as infile: # Abre o arquivo assembly para leitura
        for line_num, line in enumerate(infile, 1): # Itera sobre cada linha
            line = line.split(';')[0] # Remove os comentários
            line = line.strip().lower() # Remove espaços do início/fim e converte a linha inteira para minúsculas
                                        # Para que "ADD", "add", "Add" sejam tratados da mesma forma

            if not line: # ignora se a linha ficar vazia após remover comentários e espaços
                continue

            # Tokeniza a linha: Substitui vírgulas por espaços para que re.split possa dividir corretamente
            # re.split(r'[,\s]+', line) divide a string por um ou mais espaços ou vírgulas,
            # lidando com múltiplos delimitadores ou espaços extras
            tokens = re.split(r'[,\s]+', line)
            
            # Filtra quaisquer tokens vazios que possam surgir se houver múltiplos delimitadores consecutivos
            tokens = [token for token in tokens if token]

            if tokens: # Se a linha ainda tiver tokens válidos, adicione-a à lista de linhas processadas
                processed_lines.append(tokens)
    return processed_lines

# Montador Principal
def assemble(input_file, output_file):
    """
    Função principal do montador que orquestra o processo de montagem.
    Lê o arquivo assembly, processa cada instrução e escreve os bytes montados no arquivo de saída.
    """
    assembled_bytes = [] # Lista para armazenar os bytes hexadecimais gerados. Cada elemento é um byte (string hex de 2 chars).

    # Pré-processa o arquivo assembly para obter uma lista limpa de tokens por linhaa
    processed_lines = preprocess_assembly(input_file)

    # Itera sobre cada linha tokenizada do código assembly
    for line_num, tokens in enumerate(processed_lines, 1): # line_num é o número da linha original no arquivo.
        try:
            instruction = tokens[0] # A primeira palavra é sempre a instrução
            operands = tokens[1:] # O restante são os operandos

            if instruction == ".code" or instruction == ".data":
                # Ignora diretivas de seção como '.code' ou '.data', se presentes no arquivo
                continue

            # Lógica de Montagem para diferentes tipos de Instruções 
            # Instruções Aritméticas/Lógicas (ADD, SHR, SHL, NOT, AND, OR, XOR, CMP) e Load/Store (LD, ST)
            # Formato do Byte 1: OPCODE(4 bits) | R_DEST(2 bits) | R_SRC(2 bits)
            # Geram 1 byte de saída
            if instruction in ["add", "shr", "shl", "not", "and", "or", "xor", "cmp", "ld", "st"]:
                if len(operands) != 2:
                    raise ValueError(f"Instrução {instruction.upper()} requer 2 operandos (R_dest, R_src).")
                
                reg_dest_bits = REGISTERS.get(operands[0]) # Obtém os bits binários para o registrador de destino
                reg_src_bits = REGISTERS.get(operands[1]) # Obtém os bits binários para o registrador de origem

                if not reg_dest_bits:
                    raise ValueError(f"Registrador de destino inválido: {operands[0]}")
                if not reg_src_bits:
                    raise ValueError(f"Registrador de origem inválido: {operands[1]}")

                opcode_base = OPCODES[instruction] # Obtém o opcode base em binário
                byte1_bin = opcode_base + reg_dest_bits + reg_src_bits # Concatena para formar o byte binário completo
                assembled_bytes.append(convert_to_hex(byte1_bin)) # Converte para hex e adiciona à lista de bytes montados

            # Instrução DATA:
            # Gera 2 bytes de saída
            # Byte 1: Será obtido diretamente do mapeamento específico para cada registrador (data_rX)
            # Byte 2: VALOR(8 bits)
            elif instruction == "data":
                if len(operands) != 2:
                    raise ValueError("Instrução DATA requer 2 operandos (registrador, valor).")
                
                dest_reg_name = operands[0].strip().lower() # Obtém o nome do registrador (ex: "r0", "r1")
                
                # Obtém o Byte 1 HEX diretamente do mapeamento OPCODES[f"data_rX"] para alinhar com a "saída certa"
                if f"data_{dest_reg_name}" in OPCODES:
                    byte1_hex = OPCODES[f"data_{dest_reg_name}"] 
                    assembled_bytes.append(byte1_hex)
                else:
                    raise ValueError(f"Registrador inválido para DATA ou mapeamento não definido: {operands[0]}")

                # Validação CRÍTICA: Intervalo de -128 a 255 para valores DATA
                # parsed_val armazena o valor inteiro, podendo ser negativo
                parsed_val = parse_number(operands[1])

                # Verifica se o valor está dentro do range permitido para um dado de 8 bits (complemento de 2 ou sem sinal)
                if not (-128 <= parsed_val <= 255):
                    raise ValueError(f"Valor '{operands[1]}' fora do range de -128 a 255 para DATA.")

                # Converte o valor para sua representação de 8 bits
                # Se o valor original for negativo, ele é convertido para sua forma de complemento de 2
                if parsed_val < 0:
                    value_for_byte = (1 << 8) + parsed_val # Complemento de 2 para 8 bits
                else:
                    value_for_byte = parsed_val
                
                # Adiciona o segundo byte (o valor imediato), preenchendo com zeros à esquerda para 8 bits
                byte2_bin = pad_binary(bin(value_for_byte)[2:], 8)
                assembled_bytes.append(convert_to_hex(byte2_bin))

            # Instrução JMPR (Jump Register)
            # Formato: OPCODE(4 bits: "0011") | PADDING('00') (2 bits) | R_SRC(2 bits))
            # Gera 1 byte de saída
            elif instruction == "jmpr":
                if len(operands) != 1:
                    raise ValueError("Instrução JMPR requer 1 operando (registrador).")
                
                reg_src_bits = REGISTERS.get(operands[0]) # Obtém os bits binários do registrador de origem
                if not reg_src_bits:
                    raise ValueError(f"Registrador inválido para JMPR: {operands[0]}")
                
                opcode_base = OPCODES[instruction] # "0011"
                byte1_bin = opcode_base + "00" + reg_src_bits # Concatena opcode, padding e registrador
                assembled_bytes.append(convert_to_hex(byte1_bin))

            # Instruções JMP e Jumps Condicionais (JC, JA, JE, JZ, JCA, JCE, etc.)
            # Geram 2 bytes de saída
            # Byte 1: OPCODE (valor hexadecimal de 8 bits direto do mapeamento OPCODES)
            # Byte 2: ENDERECO (8 bits)
            elif instruction in ["jmp", "jc", "ja", "je", "jz", "jca", "jce", "jcz",
                                 "jcae", "jcaz", "jcez", "jcaez", "jae", "jaz", "jaez", "jez"]:
                if len(operands) != 1:
                    raise ValueError(f"Instrução {instruction.upper()} requer 1 operando (endereço).")
                
                # O OPCODE para esses jumps já está na tabela OPCODES como uma string hexadecimal de 2 dígitos (8 bits)
                byte1_hex = OPCODES[instruction]
                assembled_bytes.append(byte1_hex) # Adiciona diretamente o valor hexadecimal do opcode ao output

                # Processa o endereço imediato de 8 bits
                address = parse_number(operands[0])
                # Validação para endereços: devem estar no range de 0 a 255 (8 bits sem sinal)
                if not (0 <= address <= 255):
                    raise ValueError(f"Endereço '{operands[0]}' fora do range de 0 a 255.")
                
                byte2_bin = pad_binary(bin(address)[2:], 8) # Converte o endereço para binário e preenche para 8 bits
                assembled_bytes.append(convert_to_hex(byte2_bin)) # Converte para hex e adiciona à lista


            # Instrução CLF (Clear Flags)
            # Gera 1 byte de saída
            # Formato: OPCODE (valor binário de 8 bits completo)
            elif instruction == "clf":
                if len(operands) != 0:
                    raise ValueError("Instrução CLF não aceita operandos.")
                
                byte1_bin = OPCODES[instruction] # O opcode já é o byte binário completo "01100000"
                assembled_bytes.append(convert_to_hex(byte1_bin))

            # Instruções IN e OUT (Entrada/Saída)
            # Geram 1 byte de saída
            # Formato: OPCODE(4 bits: "0111") | TIPO_PORTA(2 bits) | REG(2 bits)
            elif instruction in ["in", "out"]:
                if len(operands) != 2:
                    raise ValueError(f"Instrução {instruction.upper()} requer 2 operandos (porta, registrador).")
                
                port_type = operands[0].strip().lower() # Extrai e normaliza o tipo da porta (data ou addr)
                reg_str = operands[1].strip().lower() # Extrai e normaliza o nome do registrador

                reg_bits = REGISTERS.get(reg_str) # Obtém os bits binários do registrad´r
                if not reg_bits:
                    raise ValueError(f"Registrador inválido para I/O: {reg_str}")

                opcode_base = OPCODES[instruction] # Obtém o opcode base para IN/OUT ("0111")

                # Constrói os bits que representam o tipo de porta e o registrador
                # Padrões: IN data: 00RR | IN addr: 01RR | OUT data: 10RR | OUT addr: 11RR
                port_reg_combined_bits = ""
                if instruction == "in":
                    if port_type == "data":
                        port_reg_combined_bits = "00" + reg_bits
                    elif port_type == "addr":
                        port_reg_combined_bits = "01" + reg_bits
                    else:
                        raise ValueError(f"Tipo de porta inválido para IN: {port_type}. Use 'data' ou 'addr'.")
                elif instruction == "out":
                    if port_type == "data":
                        port_reg_combined_bits = "10" + reg_bits
                    elif port_type == "addr":
                        port_reg_combined_bits = "11" + reg_bits
                    else:
                        raise ValueError(f"Tipo de porta inválido para OUT: {port_type}. Use 'data' ou 'addr'.")
                
                byte1_bin = opcode_base + port_reg_combined_bits # Concatena tudo para formar o byte
                assembled_bytes.append(convert_to_hex(byte1_bin))

            else:
                # Se a instrução não for reconhecida, informa um erro
                raise ValueError(f"Instrução desconhecida: {instruction}")

        except ValueError as e:
            # Bloco para informar erros específicos de validação de valores ou formatos
            # Imprime uma mensagem de erro detalhada no console (stderr) e encerra o programa
            print(f"Erro na linha {line_num}: {' '.join(tokens)} - {e}", file=sys.stderr)
            sys.exit(1) # Sai do programa com um código de erro
        except Exception as e:
            # Bloco para capturar qualquer outro erro inesperado que possa ocorrer
            # Imprime uma mensagem de erro genérica e encerra o programa
            print(f"Erro inesperado na linha {line_num}: {' '.join(tokens)} - {e}", file=sys.stderr)
            sys.exit(1) # Sai do programa com um código de erro

    # Geração do Arquivo de Saída
    # Abre o arquivo de saída no modo de escrita (w)
    with open(output_file, 'w') as outfile:
        # Cabeçalho padrão para o formato de saída
        outfile.write("v3.0 hex words plain\n")
        # Itera sobre cada byte hexadecimal montado e o escreve em uma nova linha no arquivo
        for hex_byte in assembled_bytes:
            outfile.write(f"{hex_byte}\n")

#Execução a partir da linha de comando
if __name__ == "__main__":
    # Verifica se o número correto de argumentos foi passado na linha de comando
    if len(sys.argv) != 3:
        print("Uso: python3 montador.py <arquivo_assembly.asm> <arquivo_saida.txt>", file=sys.stderr)
        sys.exit(1) # Sai com erro se os argumentos forem inválidos

    input_asm_file = sys.argv[1] # O primeiro argumento é o nome do arquivo assembly de entrada
    output_txt_file = sys.argv[2] # O segundo argumento é o nome do arquivo de saída

    # Chama a função principal do montador para iniciar o processo
    assemble(input_asm_file, output_txt_file)
