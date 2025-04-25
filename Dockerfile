# Wybieramy oficjalny obraz Pythona jako bazę
FROM python:3.9-slim

# Ustawiamy katalog roboczy
WORKDIR /app

# Kopiujemy plik requirements.txt do obrazu
COPY requirements.txt /app/

# Instalujemy zależności
RUN pip install --no-cache-dir -r requirements.txt

# Kopiujemy cały kod aplikacji do obrazu
COPY . /app/

# Instalujemy gunicorn
RUN pip install gunicorn

# Uruchamiamy aplikację za pomocą gunicorna na porcie 5100
CMD ["gunicorn", "-b", "0.0.0.0:5100", "app:app"]
