# ![PastiePie Logo](https://pastiepie.me/static/images/logo_tp-min.png) PastiePie

🚀 **PastiePie** is a simple and secure pastebin application written in Go. It allows users to paste content and receive a unique link to share it with others. PastiePie focuses on data security by storing pastes in an encrypted format using AES256.  It was co-written with the help of ChatGPT.

## 🌟 Features

- ✏️ **Easy Content Pasting**: Paste any content and get a unique link instantly.
- 🔒 **End-to-End Encryption**: All pastes are stored securely using AES256 encryption.
- 🖥️ **Web Interface**: A user-friendly web interface built with static HTML, served by Nginx.
- 🚢 **Dockerized Deployment**: Easily deploy PastiePie using Docker.
- 🛡️ **Secure Sharing**: Provides unique links for accessing encrypted pastes, ensuring privacy.

## 🛠️ Tech Stack

- **Language**: Go (Golang) 🐹
- **Database**: SQLite (encrypted using AES256) 💾
- **Web Server**: Nginx 🌐
- **Containerization**: Docker 🐳

## 📦 Installation

### Prerequisites

- [Docker](https://www.docker.com/) 🐋
- [Railway](https://railway.app/) (Optional) 🚂
- Git

### Steps

1. **Clone the Repository**

   ```sh
   git clone https://github.com/greysquirr3l/PastiePie.git
   cd PastiePie
   ```

2. **Set Up Environment Variables**

   PastiePie requires some environment variables to be set for encryption and security:

   - ~~`SSL_CERT`: Path to the SSL certificate.~~
   - ~~`SSL_KEY`: Path to the SSL key.~~
   - `MASTER_KEY`: 32-byte AES key for encryption.

   Example:
   ```sh
   export SSL_CERT="/path/to/cert.pem"
   export SSL_KEY="/path/to/key.pem"
   export AES_KEY="your-32-byte-aes-key"
   ```

3. **Build and Run with Docker**

   ```sh
   docker build -t pastiepie .
   docker run -p 8080:8080 --env-file .env pastiepie
   ```

   🚀 Your application should now be running on `http://localhost:8080`.

## 🌐 Usage

1. **Paste Content**: Visit the PastiePie web interface and paste your content.
2. **Get a Unique Link**: After submission, you’ll receive a unique link to share your paste.
3. **Access Pastes**: Open the unique link to view the content securely.

## 🚀 Deploying on Railway

1. Connect your GitHub repository to [Railway](https://railway.app/).
2. Add the necessary environment variables (~~`SSL_CERT`~~, ~~`SSL_KEY`~~, `MASTER_KEY`) via Railway's environment settings.
3. Deploy the application by following the Railway deployment process.

## 📜 License

This project is licensed under the MIT License. 📄 See [LICENSE](./LICENSE) for more details.

## 🤝 Contributing

Contributions are welcome! 🎉 Please fork the repository and open a pull request to get started.

1. Fork the Project 🍴
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`) 🌿
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`) 💬
4. Push to the Branch (`git push origin feature/AmazingFeature`) 🚀
5. Open a Pull Request 📥

## 💡 Roadmap

- [ ] Add user authentication 🔑
- [ ] Improve the UI for a better user experience 🎨
- [ ] Add support for paste expiration ⏲️

## 🐛 Reporting Issues

If you find a bug or have a feature request, please create an issue on GitHub. 🐞 Your feedback helps make PastiePie better for everyone!

## 📧 Contact

👨‍💻 **Nick Campbell**  
✉️ Email: [campbellnick000@gmail.com](mailto:campbellnick000@gmail.com)  
🌐 [LinkedIn](https://linkedin.com/in/nickcampbell)

---

⚡️ Built with love and a focus on privacy and security. Happy pasting! 📝✨
