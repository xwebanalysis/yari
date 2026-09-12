FROM node:24

WORKDIR /app

COPY package*.json ./

RUN npm ci || npm install

COPY . .

EXPOSE 4250

CMD ["npm", "start"]
