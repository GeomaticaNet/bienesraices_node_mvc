import { exit } from 'node:process';
import categorias from "./categorias.js";
import precios from './precios.js';
import usuarios from './usuarios.js';
import db from "../config/db.js";
import { Categoria, Precio, Usuario } from '../models/index.js'


const importarDatos = async () => {
    try {
        // Autenticar
        await db.authenticate()

        // Generar las columnas
        await db.sync()

        // Insertamos los datos (precios, categorias, o lo que fuese...)
        /* Con este metodo primero categoria bloquea la creacion de precios
            await Categoria.bulkCreate(categorias);
            await Precio.bulkCreate(precios);*/

        // Mejor con promise.all
        // Con este metodo: los dos procesos inician al mismo tiempo.
        await Promise.all([
            Categoria.bulkCreate(categorias),
            Precio.bulkCreate(precios),
            Usuario.bulkCreate(usuarios)
        ])


console.log('Datos importados correctamente');
exit(); // si termina pero fue correcto

    } catch (error) {
    console.log(error)
    exit(1); // termina pero hay error
}
}


const eliminarDatos = async () => {
    try {
        await db.sync({ force: true })
        console.log('Datos eliminados correctamente');
        exit();
    } catch (error) {
        console.log(error)
        exit(1);
    }
}



if (process.argv[2] === "-i") {
    importarDatos();
}

if (process.argv[2] === "-e") {
    eliminarDatos();
}

//"db:importar":"node ./seed/seeder.js -i"