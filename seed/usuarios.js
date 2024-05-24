import bcrypt from "bcrypt";

const usuarios = [
    {
        nombre: "Matias",
        email: "mjs.sendra@gmail.com",
        confirmado: 1,
        password: bcrypt.hashSync('password', 10)
    }
]

export default usuarios;