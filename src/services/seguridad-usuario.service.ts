import {injectable, /* inject, */ BindingScope, ResolutionSession} from '@loopback/core';
import {repository} from '@loopback/repository';
import {report} from 'process';
import {Credenciales, Usuario} from '../models';
import {UsuarioRepository} from '../repositories';
const generator = require('generate-password');
const MD5 = require('crypto-js/md5');

@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadUsuarioService {
  constructor(
    @repository (UsuarioRepository)
    public repositorioUsuario : UsuarioRepository
  ) {}

  /**
   * Crear una clave aleatoria
   * @returns Cadena aleatoria de n caracteres
   */

  creartextoAleatorio(n : number): string {
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
  cifrarTexto(cadena: string) : string {
    let cadenaCifrada = MD5(cadena).toString();
    return cadenaCifrada;
  }

/**
 * Se busca un usuario por sus credenciales de acceso
 * @param credenciales Credenciales del usuario
 * @returns Usuaio encontrado o null
 */
  async identificarUsuario(credenciales : Credenciales): Promise < Usuario|null> {
    let ususario = await this.repositorioUsuario.findOne({
      where:{
        correo : credenciales.correo,
        clave : credenciales.clave
      }
    })
    return ususario as Usuario

  }
}
