# 🧠 Password Manager

Aplicação desktop construída com [Tauri](https://tauri.app/) e **Rust**, para gerenciar credenciais de forma simples, rápida e segura no ambiente local.  
A interface gráfica permite cadastrar, visualizar, atualizar e remover registos armazenados num ficheiro protegido na pasta de dados da aplicação.

---

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Tauri](https://img.shields.io/badge/Tauri-FFC131?style=for-the-badge&logo=tauri&logoColor=black)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)
![Status](https://img.shields.io/badge/status-em%20desenvolvimento-orange?style=for-the-badge)

---

## ✨ Funcionalidades

- 📇 **Gestão de credenciais:** serviço, utilizador e password.
- 📝 **Edição direta** de credenciais existentes.
- 🗑️ **Remoção segura** de registos com confirmação.
- 💾 **Persistência automática** num ficheiro JSON local.
- 🌓 **Interface moderna** com tema escuro responsivo.
- 🧩 **Separação entre front-end e backend** (HTML/JS + Rust/Tauri).

---

## 🧰 Pré-requisitos

- [Rust](https://www.rust-lang.org/tools/install) `1.70` ou superior  
- [Node.js](https://nodejs.org/) `18` ou superior  
  *(necessário apenas para executar comandos do Tauri e gerir dependências front-end)*  
- Dependências do sistema exigidas pelo Tauri  
  → [Documentação oficial](https://tauri.app/v1/guides/getting-started/prerequisites)

---

## 📁 Estrutura do Projeto

```
password_manager/
├── src/                     # Interface estática (HTML, CSS e JS)
│   └── index.html
├── src_tauri/               # Backend Tauri + Rust
│   ├── src/
│   │   └── main.rs          # Código principal da aplicação (comandos Tauri)
│   ├── icons/
│   │   └── icon.ico         # Ícone da aplicação
│   ├── build.rs             # Script de build
│   ├── Cargo.toml           # Dependências Rust
│   └── tauri.conf.json      # Configuração do Tauri
├── LICENSE
├── package.json
├── package-lock.json
└── README.md
```

---

## 🚀 Executar em modo desenvolvimento

1. Instale as dependências Rust e JavaScript mencionadas nos pré-requisitos.
2. No diretório raiz do projeto, execute:

   ```bash
   npm install
   npx tauri dev
   ```

   > O Tauri carregará automaticamente os ficheiros estáticos do diretório `src`.

---

## 🏗️ Gerar uma build

Para criar o executável final:

```bash
npm install
npx tauri build
```

Os binários serão gerados em:
```
src_tauri/target/release/
```

---

## 🔒 Armazenamento local

As credenciais são guardadas num ficheiro `passwords.json` dentro da pasta de dados do sistema, por exemplo:

- **Windows:** `%APPDATA%\password_manager\`
- **Linux:** `~/.local/share/password_manager/`
- **macOS:** `~/Library/Application Support/password_manager/`

> ⚠️ Os dados são guardados em **texto JSON simples** apenas para demonstração.  
> Recomenda-se adicionar **criptografia** antes de usar este app em contexto real.

---

## 🧭 Roadmap

Próximas funcionalidades planejadas:

- [x] 🔐 Criptografia AES para o ficheiro `passwords.json`
- [ ] 🔑 Geração de senhas seguras com personalização
- [ ] 🧍 Autenticação local (PIN / master password)
- [ ] 🔍 Barra de pesquisa e filtragem de credenciais
- [ ] 📦 Exportação e importação de dados (JSON / CSV)
- [ ] 🌐 Sincronização opcional com armazenamento remoto
- [ ] 🧱 Interface em Vue.js ou React (migrar de HTML estático)
- [ ] 🧪 Testes automatizados Rust (unitários e integração)

---

## 🤝 Contribuir

1. Faça um fork do repositório  
2. Crie uma branch para a sua funcionalidade:  
   ```bash
   git checkout -b minha-feature
   ```
3. Implemente as alterações com commits claros  
4. Abra um **Pull Request** explicando as mudanças

---

## 📜 Licença

Distribuído sob a licença **MIT**.  
Consulte o ficheiro [LICENSE](LICENSE) para mais detalhes.

---
