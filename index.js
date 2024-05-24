// Importamos librerías.
//const express = require('express'); // CommonJS
import express from 'express';  // ECMAScript Modules
import csrf from 'csurf';
import cookieParser from 'cookie-parser';
import usuarioRoutes from './routes/usuarioRoutes.js';
import propiedadesRoutes from './routes/propiedadesRoutes.js';
import appRoutes from './routes/appRoutes.js'
import apiRoutes from "./routes/apiRoutes.js";

import db from './config/db.js';


// Crear la app
const app = express();

// Habilitar lectura de datos de formularios
app.use(express.urlencoded({ extended: true }));

// Habilitar Cookie Parser
app.use(cookieParser());

// Habilitar CSRF
app.use(csrf({ cookie: true }));


// Conexión a la base de datos
try {
    await db.authenticate();
    db.sync();
    console.log('Conexión correcta a la Base de datos');
} catch (error) {
    console.log(error);
}


// Habilitar Pug
app.set('view engine', 'pug')
app.set('views', './views')

// Carpeta Pública
app.use(express.static('public'))


// Routing: Middleware de express

// En vez de get, usar "use", y busca todas las rutas que inicien con una diagonal.
app.use('/', appRoutes)
app.use('/auth', usuarioRoutes)
app.use('/', propiedadesRoutes)
app.use('/api', apiRoutes)





// Definir un puerto y arrancar el proyecto
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`El servidor esta funcionando en el puerto ${port}`);
});