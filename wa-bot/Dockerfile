FROM node:20-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json .
RUN npm install --production

COPY . .

RUN mkdir -p /app/wa-auth

EXPOSE 3001

CMD ["node", "index.js"]
