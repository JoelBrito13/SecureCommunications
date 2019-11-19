# SecureCommunications

O projeto desenvolvido, conta com um servidor e um cliente cuja finalidade é a de envio de um ficheiro do cliente para o servidor, porém o conteúdo das mensagens enviadas é cifrado para que possa ser interceptado, porém não reconhecido. O servidor e o cliente acordam em um algoritmo e realizam a troca das chaves por meio do processo de troca de chaves, o Die-Hellman. Alguns outros mecanismos são melhor exemplificados abaixo.    

## Acordos de Algoritmos de Criptografía
O sistema possui a implementação de dois algoritmos, o AES com o modo CBC, e o Salsa20. Para encriptar utilizando o AES, é preciso de um array inicial acordado entre os dois nós, o Salsa não. Quando opta-se por utilizar o AES, o cliente enviar o vetor inicial durante o processo de troca de chaves, o servidor identifica este vetor e passa a utilizar o AES, caso o contrário utilizará o Salsa20.

## Acordos de Algoritmos de Criptografía
Todas o conteúdo das mensagens é cifrado, incluindo o nome do próprio ficheiro, o algoritmo é o AES ou o Salsa20, conforme acordado anteriormente. 

## Suporte para Integridade
O cliente enviar sempre junto com os dados cifrados, o mac da codificação, este que também é gerado do lado do servidor e comparado para verificar se há alguma concordância. Se houver, é registado o erro e o processo para.

## Rotação de chave
Implementamos uma regra lógica bem simples que contabiliza as mensagens enviadas, e a cada 16, ou seja, 15 kilobytes, inicia o processo de troca de chaves, Diffie-Hellman, e salva a posição do ficheiro para retornar a enviar do ponto exato da última mensagem.
É possível implementar uma alteração dos algoritmos de cifragem durante o processo de envios, mas não a concretizamos.



## Fluxo das Mensagens
<img src="presentation/MessageFlow.png">


## Conteúdo das Mensagens

### Server Messages
    { 'type': 'DH_REP', 'key': public_dh_key }
    { 'type': 'OK' }
    { 'type': 'ERROR', 'message': 'See server' }

### Client Messages
    { 'type': 'DH_REQ', 'parameters': public_parameters, 'key': public_dh_key, 'initial_vector': os.urandom(16)  }
    { 'type': 'OPEN', 'file_name': cipher_name }
    { 'type': 'DATA' , 'data': encripted_file_fragment, 'MAC': signature_cipher&key }
    { 'type': 'CLOSE' }


## Referencias
Para além das dependências iniciais do projeto fonte, usamos o algoritmo Salsa20 proviniente do [Legrandin](https://github.com/Legrandin/pycryptodome)
