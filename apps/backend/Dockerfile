FROM node:20-alpine

WORKDIR /app

COPY apps/backend/package*.json ./
RUN npm install

COPY apps/backend .

RUN npm run build

CMD ["npm", "run", "start:dev"]
