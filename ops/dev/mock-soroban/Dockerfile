FROM node:18-alpine

WORKDIR /app

COPY server.js ./

ENV PORT=8000
ENV NODE_ENV=development

EXPOSE 8000

CMD ["node", "server.js"]
