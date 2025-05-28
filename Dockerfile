FROM python:3.10

# Security setup (disarankan HF)
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"

# Set working dir
WORKDIR /code

# Copy and install dependencies
COPY --chown=user:0 requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy all app files
COPY --chown=user:0 . .

# Jalankan FastAPI (dari app.py)
CMD ["python", "app.py"]
