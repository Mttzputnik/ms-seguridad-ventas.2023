import {injectable, /* inject, */ BindingScope, ResolutionSession} from '@loopback/core';
import {repository} from '@loopback/repository';
import {report} from 'process';
import {ConfiguracionSeguridad} from '../config/seguridad.config';
import {Credenciales, FactorDeAutenticacionPorCodigo, Login, Usuario} from '../models';
import {LoginRepository, UsuarioRepository} from '../repositories';
const generator = require('generate-password');
const MD5 = require('crypto-js/md5');
var jwt = require('jsonwebtoken');

@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadUsuarioService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository,
    @repository(LoginRepository)
    public repositorioLogin: LoginRepository
  ) { }

  /**
   * Crear una clave aleatoria
   * @returns Cadena aleatoria de n caracteres
   */

  creartextoAleatorio(n: number): string {
    let clave = generator.generate({
      length: 10,
      numbers: true,
    });
    return clave;
  }
  /**
   * Cifrar una cadena con metodo md5
   * @param cadena Texto a cifrar
   * @returns cadena cifrada con md5
   */
  cifrarTexto(cadena: string): string {
    let cadenaCifrada = MD5(cadena).toString();
    return cadenaCifrada;
  }

  /**
   * Se busca un usuario por sus credenciales de acceso
   * @param credenciales Credenciales del usuario
   * @returns Usuaio encontrado o null
   */
  async identificarUsuario(credenciales: Credenciales): Promise<Usuario | null> {
    let ususario = await this.repositorioUsuario.findOne({
      where: {
        correo: credenciales.correo,
        clave: credenciales.clave
      }
    })
    return ususario as Usuario

  }

  /**
   * Valida un codigo de 2fa para un usuario
   * @param credenciales2fa Credenciales del usuario con el codiugo del segundo factor de autenticacion
   * @returns El registro de login o null
   */

  async validarcodigo2fa(credenciales2fa: FactorDeAutenticacionPorCodigo): Promise<Usuario | null> {
    let login = await this.repositorioLogin.findOne({
      where: {
        usuarioId: credenciales2fa.usuarioId,
        codigo2Fa: credenciales2fa.codigo2fa,
        estadoCodigo2Fa: false
      }
    })
    if (login) {
      let usuario = await this.repositorioUsuario.findById(credenciales2fa.usuarioId)
      return usuario
    }
    return null
  }

  /**
   * Generacion de JWT
   * @param usuario Informacion del usuario
   * @returns token
   */
  crearToken(usuario: Usuario): string {
    let datos = {
      name: `${usuario.primerNombre} ${usuario.segundoNombre} ${usuario.primerApellido} ${usuario.segundoApellido}`,
      role: usuario.rolId,
      email: usuario.correo
    }
    let token = jwt.sign(datos, ConfiguracionSeguridad.claveJWT);
    return token
  }

}

