# Password Manager

Aplicação desktop construída com [Tauri](https://tauri.app/) e Rust para gerenciar credenciais de forma simples e local. A interface gráfica permite cadastrar, visualizar, atualizar e remover registos armazenados em um ficheiro seguro na pasta de dados do aplicativo.

## Funcionalidades

- 📇 Cadastro de credenciais contendo serviço, user e password.
- 📝 Edição direta das credenciais existentes.
- 🗑️ Remoção de entradas indesejadas com confirmação.
- 💾 Persistência automática em arquivo JSON localizado no diretório de dados da aplicação.
- 🌓 Layout responsivo com tema escuro moderno.

## Pré-requisitos

- [Rust](https://www.rust-lang.org/tools/install) 1.70 ou superior.
- [Node.js](https://nodejs.org/) 18 ou superior (necessário para executar os comandos de desenvolvimento do front-end, mesmo em um projeto estático).
- Dependências do sistema exigidas pelo Tauri (verifique a [documentação oficial](https://tauri.app/v1/guides/getting-started/prerequisites)).

## Estrutura do projeto

```
password_manager/
├── src/                  # Interface gráfica (HTML, CSS e JS)
├── src-tauri/            # Código Rust com comandos e configuração Tauri
│   ├── src/main.rs
│   ├── Cargo.toml
│   └── tauri.conf.json
├── LICENSE
└── README.md
```

## Executando em modo desenvolvimento

1. Instale as dependências Rust e JavaScript mencionadas nos pré-requisitos.
2. Execute o servidor de desenvolvimento do Tauri:

   ```bash
   npm install
   npx tauri dev
   ```

   > Como a interface é totalmente estática, não há scripts extras de build — o Tauri carrega os arquivos diretamente do diretório `src`.

## Gerar uma build

Para produzir o executável da aplicação:

```bash
npm install
npx tauri build
```

Os artefatos gerados ficarão em `src-tauri/target/release/`.

## Como funciona o armazenamento

As credenciais são persistidas em um arquivo `passwords.json` dentro da pasta de dados fornecida pelo sistema operativo (por exemplo, `~/.local/share/password_manager/` no Linux). O arquivo é serializado em JSON apenas para fins de demonstração. Considere integrar uma camada de criptografia antes de usar esta aplicação em ambientes reais.

## Contribuindo

1. Faça um fork do repositório.
2. Crie uma branch para sua funcionalidade: `git checkout -b minha-feature`.
3. Implemente a alteração acompanhada de testes quando aplicável.
4. Abra um Pull Request descrevendo a motivação e as principais mudanças.

## Licença

Distribuído sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE) para detalhes.