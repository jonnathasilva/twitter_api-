import Router from "koa-router";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";

export const router = new Router();

const prisma = new PrismaClient();

router.get("/tweets", async (ctx) => {
  const [, token] = ctx.request.headers?.authorization?.split(" ") || [];

  if (!token) {
    ctx.status = 401;
    return;
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    const tweets = await prisma.tweet.findMany({
      include: {
        user: true,
      },
    });

    ctx.body = tweets;
  } catch (error) {
    if (typeof error === "JsonWebTokenError") {
      ctx.status = 401;
      return;
    }

    ctx.status = 500;
    return;
  }
});

router.post("/tweets", async (ctx) => {
  const [, token] = ctx.request.headers?.authorization?.split(" ") || [];

  if (!token) {
    ctx.status = 401;
    return;
  }

  if (!ctx.request.body.text || ctx.request.body.text === " ") {
    ctx.body = { message: "Digite um texto" };
    ctx.status = 422;
    return;
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    const tweets = await prisma.tweet.create({
      data: {
        userId: payload.sub,
        text: ctx.request.body.text,
      },
    });

    ctx.body = tweets;
  } catch (error) {
    ctx.status = 401;
    return;
  }
});

router.post("/signup", async (ctx) => {
  const saltRounds = 10;
  const password = bcrypt.hashSync(ctx.request.body.password, saltRounds);

  try {
    const user = await prisma.user.create({
      data: {
        name: ctx.request.body.name,
        username: ctx.request.body.username,
        email: ctx.request.body.email,
        password,
      },
    });

    const accessToken = jwt.sign(
      {
        sub: user.id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    ctx.body = {
      id: user.id,
      name: user.name,
      username: user.username,
      email: user.email,
      accessToken,
    };
  } catch (err) {
    if (err.meta && !err.meta.target) {
      ctx.status = 422;
      ctx.body = { message: "E-mail ou nome de usuario já existe." };
      return;
    }

    ctx.status = 500;
    ctx.body = { message: "Internal error." };
  }
});

router.get("/login", async (ctx) => {
  const [, token] = ctx.request.headers.authorization.split(" ");
  const [email, plainTextpassword] = Buffer.from(token, "base64")
    .toString()
    .split(":");

  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user) {
    ctx.body = { message: "E-mail invalido" };
    ctx.status = 404;
    return;
  }

  const passwordMatch = bcrypt.compareSync(plainTextpassword, user.password);

  console.log(passwordMatch);

  if (passwordMatch) {
    const accessToken = jwt.sign(
      {
        sub: user.id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    return (ctx.body = {
      id: user.id,
      name: user.name,
      username: user.username,
      email: user.email,
      accessToken,
    });
  }

  ctx.body = { message: "Senha invalida" };
  ctx.status = 404;
});

router.get("/auth", async (ctx) => {
  const [, token] = ctx.request.headers.authorization.split(" ");

  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  if (decoded) {
    ctx.status = 200;
    return;
  }

  ctx.status = 401;
  return;
});
