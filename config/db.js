import { Sequelize } from "sequelize";
import dotenv from 'dotenv';
dotenv.config({path:'.env'})

const db = new Sequelize(process.env.BD_NOMBRE, process.env.BD_USER, process.env.BD_PASS, {

    host: process.env.BD_HOST,
    port: 3307,
    dialect: 'mysql',
    // define: establece columnas de quien creo cada cosa o elimino etc.
    define: {
        timestamps: true
    },
    // configura como va a hacer el comportamiento para conexiones nuevas o existentes, para optimizar rendimiento de la bbdd: ejemplo: max: maximo de conexiones simultaneas, acquire: 30 seg tiempo tratando de conectar, e idle: 10seg si no hay nada de movimientos le da 10 segundos para finalizar la conexión.
    pool: {
        max: 5,
        min: 0,
        acquire: 30000,
        idle: 10000
    },
    operatorsAliases: false
});

export default db;
