FROM python:3.13-slim

WORKDIR /app

# gmpy2 needs mpfr headers to build
RUN apt-get update && \
    apt-get -y install libmpfr-dev libmpc-dev && \
    rm -rf /var/lib/apt/lists/* && \
    python -m pip install --upgrade pip

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir badkeys
RUN badkeys --update-bl-and-urls

CMD ["badkeys"]
