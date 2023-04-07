import {service} from '@loopback/core';
import {
  Count,
  CountSchema,
  Filter,
  FilterExcludingWhere,
  repository,
  Where,
} from '@loopback/repository';
import {
  post,
  param,
  get,
  getModelSchemaRef,
  patch,
  put,
  del,
  requestBody,
  response,
  HttpErrors,
} from '@loopback/rest';
import {Credenciales, FactorDeAutenticacionPorCodigo, Login, Usuario} from '../models';
import {LoginRepository, UsuarioRepository} from '../repositories';
import {SeguridadUsuarioService} from '../services';

export class UsuarioController {
  constructor(
    @repository(UsuarioRepository)
    public usuarioRepository: UsuarioRepository,

    @service(SeguridadUsuarioService)
    public servicioSeguridad: SeguridadUsuarioService,
    @repository(LoginRepository)
    public repositorioLogin: LoginRepository
  ) { }

  @post('/usuario')
  @response(200, {
    description: 'Usuario model instance',
    content: {'application/json': {schema: getModelSchemaRef(Usuario)}},
  })
  async create(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {
            title: 'NewUsuario',
            exclude: ['_id'],
          }),
        },
      },
    })
    usuario: Omit<Usuario, '_id'>,
  ): Promise<Usuario> {

    // crear la clave

    let clave = this.servicioSeguridad.creartextoAleatorio(10);
    console.log(clave)

    // cifrar la clave

    let claveCifrada = this.servicioSeguridad.cifrarTexto(clave);

    // asignar la clave cifrada al usuario

    usuario.clave = claveCifrada;

    // enviar un correo electronico de notificacion

    return this.usuarioRepository.create(usuario);
  }

  @get('/usuario/count')
  @response(200, {
    description: 'Usuario model count',
    content: {'application/json': {schema: CountSchema}},
  })
  async count(
    @param.where(Usuario) where?: Where<Usuario>,
  ): Promise<Count> {
    return this.usuarioRepository.count(where);
  }

  @get('/usuario')
  @response(200, {
    description: 'Array of Usuario model instances',
    content: {
      'application/json': {
        schema: {
          type: 'array',
          items: getModelSchemaRef(Usuario, {includeRelations: true}),
        },
      },
    },
  })
  async find(
    @param.filter(Usuario) filter?: Filter<Usuario>,
  ): Promise<Usuario[]> {
    return this.usuarioRepository.find(filter);
  }

  @patch('/usuario')
  @response(200, {
    description: 'Usuario PATCH success count',
    content: {'application/json': {schema: CountSchema}},
  })
  async updateAll(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {partial: true}),
        },
      },
    })
    usuario: Usuario,
    @param.where(Usuario) where?: Where<Usuario>,
  ): Promise<Count> {
    return this.usuarioRepository.updateAll(usuario, where);
  }

  @get('/usuario/{id}')
  @response(200, {
    description: 'Usuario model instance',
    content: {
      'application/json': {
        schema: getModelSchemaRef(Usuario, {includeRelations: true}),
      },
    },
  })
  async findById(
    @param.path.string('id') id: string,
    @param.filter(Usuario, {exclude: 'where'}) filter?: FilterExcludingWhere<Usuario>
  ): Promise<Usuario> {
    return this.usuarioRepository.findById(id, filter);
  }

  @patch('/usuario/{id}')
  @response(204, {
    description: 'Usuario PATCH success',
  })
  async updateById(
    @param.path.string('id') id: string,
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {partial: true}),
        },
      },
    })
    usuario: Usuario,
  ): Promise<void> {
    await this.usuarioRepository.updateById(id, usuario);
  }

  @put('/usuario/{id}')
  @response(204, {
    description: 'Usuario PUT success',
  })
  async replaceById(
    @param.path.string('id') id: string,
    @requestBody() usuario: Usuario,
  ): Promise<void> {
    await this.usuarioRepository.replaceById(id, usuario);
  }

  @del('/usuario/{id}')
  @response(204, {
    description: 'Usuario DELETE success',
  })
  async deleteById(@param.path.string('id') id: string): Promise<void> {
    await this.usuarioRepository.deleteById(id);
  }



  /**
   *  metodos personalizados para la API
   */

  @post('/identificar-usuario')
  @response(200, {
    description: "identificar un usuario por correo y clave",
    content: {'application/json': {schema: getModelSchemaRef(Usuario)}}
  })

  async identificarUsuario(
    @requestBody(
      {
        content: {
          'aplication/json': {
            schema: getModelSchemaRef(Credenciales)
          }
        }
      }
    )
    credenciales: Credenciales

  ): Promise<object> {
    let usuario = await this.servicioSeguridad.identificarUsuario(credenciales)
    if (usuario) {
      let codigo2fa = this.servicioSeguridad.creartextoAleatorio(5)
      console.log(codigo2fa)
      let login: Login = new Login()
      login.usuarioId = usuario._id!
      login.codigo2Fa = codigo2fa
      login.estadoCodigo2Fa = false
      login.token = ""
      login.estadoToken = false
      this.repositorioLogin.create(login)
      usuario.clave = ""
      //notificar al usuario via correo o sms
      return usuario
    }
    return new HttpErrors[401]("Credenciales incorrectas")
  }

  @post('/verificar-2fa')
  @response(200, {
    description: "Validar un codigo de 2fa"
  })

  async VerificarCodigo2fa(
    @requestBody(
      {
        content: {
          'aplication/json': {
            schema: getModelSchemaRef(FactorDeAutenticacionPorCodigo)
          }
        }
      }
    )
    credenciales: FactorDeAutenticacionPorCodigo

  ): Promise<object> {
    let usuario = await this.servicioSeguridad.validarcodigo2fa(credenciales)
    if (usuario) {
      let token = this.servicioSeguridad.crearToken(usuario)

      if (usuario) {
        usuario.clave = ""
        try {
          this.usuarioRepository.logins(usuario._id).patch({
            estadoCodigo2Fa: true,
            token : token

          },
            {
              estadoCodigo2Fa: false
            })
        } catch {
          console.log("No se ha almacenado el cambio del estado de token en la base de datos. ")
        }

        return {
          user: usuario,
          token: token
        }
      }
    }
    return new HttpErrors[401]("Codigo del segundo factor de autenticacion invalido para el usuario definido")
  }
}
