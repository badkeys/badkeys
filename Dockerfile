FROM python:3-slim

RUN pip install --no-cache-dir badkeys && \
    badkeys --update-bl-and-urls

CMD ["badkeys"]
