# Citizen AI – Intelligent Citizen Engagement Platform

Citizen AI is an AI-powered platform designed to enhance citizen engagement by providing real-time responses, feedback management, and interactive dashboards. Built with **Flask**, it integrates front-end templates and a database to deliver a complete web solution.

---

## 🚀 Features

* User registration and login system
* Admin dashboard for managing citizens
* AI-powered chatbot interface
* Feedback submission and tracking
* Service information pages
* SQLite database integration
* Responsive UI with HTML/CSS templates

---

## 📂 Project Structure

```
Project Files/
│── app.py                # Main Flask app
│── requirements.txt       # Python dependencies
│── citizen_ai.db          # SQLite database
│── .env                   # Environment variables
│── static/
│   ├── styles.css         # CSS styles
│   └── readme.md
│── templates/
│   ├── index.html         # Homepage
│   ├── login.html         # User login
│   ├── register.html      # User registration
│   ├── dashboard.html     # User dashboard
│   ├── admin.html         # Admin login
│   ├── admin_dashboard.html # Admin control panel
│   ├── chat.html          # Chat interface
│   ├── feedback.html      # Feedback form
│   ├── about.html         # About page
│   ├── services.html      # Services info
│   └── base.html          # Common layout
│── 2.py, 3.py             # Additional scripts
```

---

## 🛠️ Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/your-username/citizen-ai.git
   cd citizen-ai/Project\ Files
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate   # On Linux/Mac
   venv\Scripts\activate      # On Windows
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables in a `.env` file (example):

   ```
   FLASK_APP=app.py
   FLASK_ENV=development
   SECRET_KEY=your-secret-key
   ```

---

## ▶️ Usage

Run the Flask app:

```bash
flask run
```

By default, the app will be available at:
👉 [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 💡 Future Enhancements

* Integration with AI/ML models (IBM Watson, OpenAI, etc.)
* Role-based authentication system
* Deployment with Docker + Nginx
* Multi-language support

---

## 🤝 Contributing

Contributions are welcome! Please fork this repository and submit a pull request with your improvements.

---

## 📜 License

This project is licensed under the MIT License. See the LICENSE file for details.
