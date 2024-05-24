import { check, validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import Usuario from '../models/Usuario.js'
import { generarJWT, generarId } from '../helpers/tokens.js'
import { emailRegistro, emailOlvidePassword } from '../helpers/emails.js'

const formularioLogin = (req, res) => {
    res.render('auth/login', {
        pagina: 'Iniciar Sesión',
        csrfToken: req.csrfToken() // generamos el token....
    })
}

const autenticar = async (req, res) => {
    // Validación
    await check('email').isEmail().withMessage('El email es obligatorio').run(req)
    await check('password').notEmpty().withMessage('El password es obligatorio').run(req)

    let resultado = validationResult(req)

    // Verificar que el resultado este vacío
    if (!resultado.isEmpty()) {
        // resultado no vacio significa que hay errores.
        return res.render('auth/login', {
            pagina: 'Iniciar Sesión',
            csrfToken: req.csrfToken(),
            errores: resultado.array(),
        })
    }

    const { email, password } = req.body;
    // Comprobar si el usuario existe
    const usuario = await Usuario.findOne({ where: { email } })
    if (!usuario) {
        return res.render('auth/login', {
            pagina: 'Iniciar Sesión',
            csrfToken: req.csrfToken(),
            errores: [{ msg: 'El usuario no existe' }],
        })
    }

    // Comprobar si el usuario esta confirmado:
    if (!usuario.confirmado) {
        return res.render('auth/login', {
            pagina: 'Iniciar Sesión',
            csrfToken: req.csrfToken(),
            errores: [{ msg: 'Tu cuenta no ha sido confirmada' }],
        })
    }

    // Revisar el password:
    if (!usuario.verificarPassword(password)) {
        return res.render('auth/login', {
            pagina: 'Iniciar Sesión',
            csrfToken: req.csrfToken(),
            errores: [{ msg: 'El password es incorrecto' }],
        })
    }

    // SI TODO LO PREVIO ES CORRECTO:
    // Autenticar al usuario:

    const token = generarJWT({ id: usuario.id, nombre: usuario.nombre })

    console.log(token);

    // Almacenar en una cookie y redirecciona a la pagina de propiedades
    return res.cookie('_token', token, {
        httpOnly: true,
        //secure: true, // true si tenemos https, ahora no lo tenemos.
        // sameSite: true
    }).redirect('/mis-propiedades');
}

const cerrarSesion = (req, res) => {

    return res.clearCookie('_token').status(200).redirect('/auth/login');
    
}

const formularioRegistro = (req, res) => {
    res.render('auth/registro', {
        pagina: 'Crear Cuenta',
        csrfToken: req.csrfToken()
    })
}

const registrar = async (req, res) => {
    // Validación:
    await check('nombre').notEmpty().withMessage('El nombre no puede ir vacío.').run(req)
    await check('email').isEmail().withMessage('Eso no parece un email.').run(req)
    await check('password').isLength({ min: 6 }).withMessage('El password debe ser de al menos 6 caracteres.').run(req)
    await check('repetir_password')
        .equals(req.body.password)
        .withMessage('Los Passwords no son iguales.')
        .run(req)

    let resultado = validationResult(req)

    // return res.json(resultado.array())

    // Verificar que el resultado este vacío
    if (!resultado.isEmpty()) {
        // resultado no vacio significa que hay errores.
        return res.render('auth/registro', {
            pagina: 'Crear Cuenta',
            csrfToken: req.csrfToken(),
            errores: resultado.array(),
            usuario: {
                nombre: req.body.nombre,
                email: req.body.email,
            }
        })
    }


    // Extraer los datos
    const { nombre, email, password } = req.body

    // Verificar que el usuario no este duplicado
    const existeUsuario = await Usuario.findOne({ where: { email } })
    if (existeUsuario) {
        return res.render('auth/registro', {
            pagina: 'Crear Cuenta',
            csrfToken: req.csrfToken(),
            errores: [{ msg: 'El usuario ya esta registrado.' }],
            usuario: {
                nombre: nombre,
                email: email
            }
        })
    }

    // Almacenar un usuario
    const usuario = await Usuario.create({
        nombre,
        email,
        password,
        token: generarId()
    })

    // Enviar email de confirmación:
    emailRegistro({
        nombre: usuario.nombre,
        email: usuario.email,
        token: usuario.token
    })



    // Mostrar mensaje de confirmación
    res.render('pug-templates/mensaje', {
        pagina: 'Cuenta creada correctamente.',
        mensaje: 'Hemos enviado un email de confirmación, presiona el enlace.'
    })
}

// Función que comprueba una cuenta
const confirmar = async (req, res) => {

    const { token } = req.params;


    // Verificar si el token es válido
    const usuario = await Usuario.findOne({ where: { token } })

    if (!usuario) {
        return res.render('auth/confirmar-cuenta', {
            pagina: 'Error al confirmar tu cuenta.',
            mensaje: 'Hubo un error al confirmar tu cuenta, intenta de nuevo.',
            error: true
        })
    }

    // Confirmar la cuenta
    usuario.token = null;
    usuario.confirmado = true;
    await usuario.save();

    res.render('auth/confirmar-cuenta', {
        pagina: 'Cuenta confirmada',
        mensaje: 'La cuenta se confirmó correctamente'
    })


};


const formularioOlvidePassword = (req, res) => {
    res.render('auth/olvide-password', {
        pagina: 'Recupera tu acceso a Bienes Raíces',
        csrfToken: req.csrfToken(),
    })
}

const resetPassword = async (req, res) => {
    // Validación:
    await check('email').isEmail().withMessage('Eso no parece un email.').run(req)


    let resultado = validationResult(req)

    // return res.json(resultado.array())

    // Verificar que el resultado este vacío
    if (!resultado.isEmpty()) {
        // resultado no vacio significa que hay errores.
        return res.render('auth/olvide-password', {
            pagina: 'Recupera tu acceso a Bienes Raíces',
            csrfToken: req.csrfToken(),
            errores: resultado.array()
        })
    }

    // Buscar el usuario
    const { email } = req.body

    const usuario = await Usuario.findOne({ where: { email } })

    if (!usuario) {
        return res.render('auth/olvide-password', {
            pagina: 'Recupera tu acceso a Bienes Raíces',
            csrfToken: req.csrfToken(),
            errores: [{ msg: 'El email no pertenece a ningún usuario' }]
        })
    }
    // Generar un token y enviar el email
    usuario.token = generarId();
    await usuario.save();

    // enviar un email
    emailOlvidePassword({
        email: usuario.email,
        nombre: usuario.nombre,
        token: usuario.token
    });

    // Renderizar mensaje de confirmación
    res.render('pug-templates/mensaje', {
        pagina: 'Reestablece tu password',
        mensaje: 'Hemos enviado un email con las instrucciones.'
    })

}

const comprobarToken = async (req, res) => {

    const { token } = req.params;
    const usuario = await Usuario.findOne({ where: { token } })
    console.log(usuario);

    if (!usuario) {
        return res.render('auth/confirmar-cuenta', {
            pagina: 'Reestablece tu Password',
            mensaje: 'Hubo un error al validar tu información, intenta de nuevo.',
            error: true
        })
    }

    // Mostrar formulario para modificar el password
    res.render('auth/reset-password', {
        pagina: 'Reestablece tu Password',
        csrfToken: req.csrfToken()
    });



}

const nuevoPassword = async (req, res) => {
    // Validar el password
    await check('password').isLength({ min: 6 }).withMessage('El password debe ser de al menos 6 caracteres.').run(req)

    let resultado = validationResult(req)

    // return res.json(resultado.array())

    // Verificar que el resultado este vacío
    if (!resultado.isEmpty()) {
        // resultado no vacio significa que hay errores.
        return res.render('auth/reset-password', {
            pagina: 'Reestablece tu password',
            csrfToken: req.csrfToken(),
            errores: resultado.array(),
        })
    }

    const { token } = req.params;
    const { password } = req.body;

    // Identificar quien hace el cambio
    const usuario = await Usuario.findOne({ where: { token } });

    // Hashear el nuevo password
    const salt = await bcrypt.genSalt(10)
    usuario.password = await bcrypt.hash(password, salt);
    usuario.token = null;

    await usuario.save();

    res.render('auth/confirmar-cuenta', {
        pagina: 'Password Reestablecido',
        mensaje: 'El password se guardó correctamente.'
    })

}

export {
    autenticar,
    cerrarSesion,
    comprobarToken,
    confirmar,
    formularioLogin,
    formularioOlvidePassword,
    formularioRegistro,
    nuevoPassword,
    registrar,
    resetPassword,
}