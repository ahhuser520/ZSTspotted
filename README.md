# ZSTspotted

**School-based spotted platform for Zespół Szkół Technicznych in Żnin, Poland**
An open-source web application that allows anonymous post submissions and public comments, with strong focus on privacy and security.

## 🧩 Project Overview

**ZSTspotted** is a lightweight full-stack application inspired by “spotted” platforms, built specifically for the students of ZST Żnin. It can easily be adapted to work in any school environment by modifying names, styles, or configuration.

## 🚀 Features

* ✅ **Anonymous post submission** – users can submit posts without revealing their identity
* 💬 **Public comments** – posts can be commented on with visible usernames
* 🔐 **Secure login** – uses salted passwords and strong SHA-512 hashing
* 🧅 **Username hashing** – usernames are also hashed for additional privacy
* 🛠️ **Admin panel** – content moderation available under `/admin` route

## ⚙️ Tech Stack

* **Backend**: [Flask](https://flask.palletsprojects.com/) (Python)
* **Frontend**: HTML + CSS
* **Database**: MySQL
* **Containerization**: Docker (includes `Dockerfile` for easy setup)

## 📦 Installation

### Requirements

* Python 3.9+
* MySQL
* Docker (optional, but recommended for easy deployment)

### Quickstart (Docker)

```bash
docker build -t zstspotted .
docker run -p 5000:5000 zstspotted
```

### Manual Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/your-user/ZSTspotted.git
   cd ZSTspotted
   ```
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```
3. Set up database connection and environment variables
4. Run the application:

   ```bash
   python app.py
   ```

## 🔐 Security Notes

* Passwords are salted and hashed using **SHA-512**
* Usernames are hashed to protect user identities
* Admin moderation panel is available at `/admin`

## 📜 License

This project is licensed under the **GNU GPL v3**.
You are free to use, modify, and redistribute under the terms of this license.

## 📬 Contact

For questions or contributions, contact the repository owner directly via **Signal**.
