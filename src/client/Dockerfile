FROM node:20-bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    krb5-user \
    libkrb5-dev \
    libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm install

COPY . .

RUN npm run build
CMD ["node", "dist/client/client.js"]