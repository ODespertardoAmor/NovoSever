require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const http = require('http');
const validator = require('validator');

// 🚀 INICIALIZAÇÃO
const app = express();
const servidor = http.createServer(app);

// 🔗 CONEXÃO BANCO DE DADOS
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log('🟢 BANCO DE DADOS CONECTADO - ROTA BRASIL 🗄️✅'))
.catch(err => console.log('🔴 ERRO DB: ', err));

// ⚙️ MIDDLEWARES
app.use(cors({ origin: "*" })); // Libera acesso para o Front
app.use(express.json()); // Ler JSON do Body

// 🔌 SOCKET.IO (TEMPO REAL - A ALMA DO APP)
const io = new Server(servidor, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

// ==================================================
// 📋 MODELOS DO BANCO (ESTRUTURA DOS DADOS) 📊🧱
// ==================================================

// 👤 MODELO USUÁRIO (Motorista e Passageiro)
const UsuarioSchema = new mongoose.Schema({
  nome: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  senha: { type: String, required: true },
  telefone: { type: String, required: true },
  foto: { type: String, default: 'https://cdn-icons-png.flaticon.com/512/64/64572.png' },
  tipo: { type: String, enum: ['passageiro', 'motorista'], required: true },
  dataCadastro: { type: Date, default: Date.now },
  
  // 🚗 DADOS EXCLUSIVOS MOTORISTA
  marca: String,
  cor: String,
  placa: String,
  cnh: String,
  online: { type: Boolean, default: false },
  localizacao: { lat: Number, lng: Number },
  
  ⭐ AVALIAÇÕES: [{
    nota: { type: Number, min:1, max:5 },
    comentario: String,
    usuarioAvaliou: { type: mongoose.Schema.Types.ObjectId, ref: 'Usuario' },
    data: { type: Date, default: Date.now }
  }],

  📊 ESTATISTICAS: {
    totalCorridas: { type: Number, default: 0 },
    valorGasto: { type: Number, default: 0 }, // Passageiro
    ganhoTotal: { type: Number, default: 0 }, // Motorista
    taxaAceite: { type: Number, default: 0 }
  }
});
const Usuario = mongoose.model('Usuario', UsuarioSchema);

// 🚘 MODELO CORRIDA
const CorridaSchema = new mongoose.Schema({
  origem: { type: String, required: true },
  destino: { type: String, required: true },
  distancia: { type: String, required: true },
  valor: { type: Number, required: true },
  status: { type: String, enum: ['aguardando', 'aceita', 'finalizada', 'cancelada'], default: 'aguardando' },
  data: { type: Date, default: Date.now },

  👤 PASSAGEIRO: { type: mongoose.Schema.Types.ObjectId, ref: 'Usuario', required: true },
  nomePassageiro: String,
  telPassageiro: String,

  🧑✈️ MOTORISTA: { type: mongoose.Schema.Types.ObjectId, ref: 'Usuario', default: null },
  nomeMotorista: String,

  ⭐ AVALIACAO_MOTORISTA: { nota: Number, comentario: String },
  ⭐ AVALIACAO_PASSAGEIRO: { nota: Number, comentario: String }
});
const Corrida = mongoose.model('Corrida', CorridaSchema);

// ==================================================
// 🔐 MIDDLEWARE DE AUTENTICAÇÃO (PROTEGE ROTAS) 🛡️
// ==================================================
const proteger = async (req, res, next) => {
  let token;
  if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
    token = req.headers.authorization.split(' ')[1];
  }
  if(!token) return res.status(401).json({erro: "Acesso negado! Faça login 🚫🔑"});

  try {
    const decodificado = jwt.verify(token, process.env.CHAVE_JWT);
    req.usuario = await Usuario.findById(decodificado.id).select('-senha');
    next();
  } catch (e) {
    res.status(401).json({erro: "Token inválido/expirado ❌"});
  }
};

// ==================================================
// 🛣️ ROTAS PRINCIPAIS (TUDO QUE O FRONT CHAMA!) 📡⚡
// ==================================================

// ✅ 1. CADASTRO /register
app.post('/register', async (req, res) => {
  try {
    const { nome, email, senha, telefone, tipo, marca, cor, placa, cnh, foto } = req.body;

    // 🧪 VALIDAÇÕES BÁSICAS
    if(!nome || !email || !senha || !telefone || !tipo) return res.status(400).json({erro: "Preencha todos os campos obrigatórios! 📝⚠️"});
    if(!validator.isEmail(email)) return res.status(400).json({erro: "E-mail inválido! 📧❌"});
    if(senha.length < 6) return res.status(400).json({erro: "Senha deve ter +6 caracteres 🔑⚠️"});
    if(await Usuario.findOne({email})) return res.status(400).json({erro: "E-mail já cadastrado! 📧🚫"});

    // 🔒 CRIPTOGRAFAR SENHA
    const salt = await bcrypt.genSalt(10);
    const senhaHash = await bcrypt.hash(senha, salt);

    // 🆕 CRIAR USUÁRIO
    const usuario = new Usuario({
      nome, email, senha: senhaHash, telefone, tipo,
      foto: foto || undefined, marca, cor, placa, cnh
    });

    await usuario.save();
    res.status(201).json({mensagem: "Conta criada com sucesso! 🥳✅"});

  } catch (e) {
    res.status(500).json({erro: "Erro no servidor 😵💫", detalhe: e.message});
  }
});

// ✅ 2. LOGIN /login
app.post('/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    const usuario = await Usuario.findOne({email});

    if(!usuario || !(await bcrypt.compare(senha, usuario.senha))){
      return res.status(401).json({erro: "E-mail ou Senha incorretos! 🔍❌"});
    }

    // 🎫 GERAR TOKEN
    const token = jwt.sign({id: usuario._id}, process.env.CHAVE_JWT, {expiresIn: process.env.TEMPO_TOKEN});

    // 📤 RETORNAR DADOS SEM SENHA
    const dadosUsuario = usuario.toObject();
    delete dadosUsuario.senha;

    res.json({token, user: dadosUsuario});

  } catch (e) {
    res.status(500).json({erro: "Erro no Login 🚧"});
  }
});

// ✅ 3. HISTÓRICO CORRIDAS MOTORISTA /corridas/motorista
app.get('/corridas/motorista', proteger, async (req, res) => {
  if(req.usuario.tipo !== 'motorista') return res.status(403).json({erro: "Apenas motoristas 🚗⛔"});
  const corridas = await Corrida.find({motorista: req.usuario._id}).sort({data: -1});
  res.json(corridas);
});

// ✅ 4. HISTÓRICO CORRIDAS PASSAGEIRO /corridas/passageiro
app.get('/corridas/passageiro', proteger, async (req, res) => {
  if(req.usuario.tipo !== 'passageiro') return res.status(403).json({erro: "Apenas passageiros 🧍⛔"});
  const corridas = await Corrida.find({passageiro: req.usuario._id}).sort({data: -1});
  res.json(corridas);
});

// ✅ 5. AVALIAR MOTORISTA /avaliar/motorista/:idMotorista/:idCorrida
app.post('/avaliar/motorista/:idMotorista/:idCorrida', proteger, async (req, res) => {
  try {
    const { nota, comentario } = req.body;
    const { idMotorista, idCorrida } = req.params;

    // 📝 SALVAR AVALIAÇÃO NO MOTORISTA
    await Usuario.findByIdAndUpdate(idMotorista, {
      $push: {avaliacoes: {nota, comentario, usuarioAvaliou: req.usuario._id}}
    });

    // 📝 SALVAR NA CORRIDA
    await Corrida.findByIdAndUpdate(idCorrida, {avaliacao_motorista: {nota, comentario}});

    res.json({sucesso: true, mensagem: "Avaliação enviada ⭐✅"});

  } catch (e) { res.status(500).json({erro: "Erro ao avaliar 😵💫"}) }
});

// ✅ 6. AVALIAR PASSAGEIRO /avaliar/passageiro/:idPassageiro/:idCorrida
app.post('/avaliar/passageiro/:idPassageiro/:idCorrida', proteger, async (req, res) => {
  try {
    const { nota, comentario } = req.body;
    const { idPassageiro, idCorrida } = req.params;

    await Usuario.findByIdAndUpdate(idPassageiro, {
      $push: {avaliacoes: {nota, comentario, usuarioAvaliou: req.usuario._id}}
    });

    await Corrida.findByIdAndUpdate(idCorrida, {avaliacao_passageiro: {nota, comentario}});

    res.json({sucesso: true});

  } catch (e) { res.status(500).json({erro: "Erro"}) }
});

// ==================================================
// ⚡ EVENTOS SOCKET.IO (TEMPO REAL - O CORAÇÃO ❤️⚡)
// ==================================================

// 📦 ARMAZENAR CONEXÕES ATIVAS
let motoristasOnline = new Map(); // chave: ID Usuario, valor: SocketID + Dados

io.on('connection', (socket) => {
  console.log('🔌 Usuário Conectou: ' + socket.id);

  // 🟢 MOTORISTA FICOU ONLINE
  socket.on('online', async (tokenJWT) => {
    try {
      const decod = jwt.verify(tokenJWT, process.env.CHAVE_JWT);
      const motorista = await Usuario.findById(decod.id);
      if(!motorista || motorista.tipo !== 'motorista') return;

      // 📌 SALVAR COMO ONLINE
      motorista.online = true;
      await motorista.save();
      
      // 📝 ADICIONAR NA LISTA GLOBAL
      motoristasOnline.set(motorista._id.toString(), {
        socketId: socket.id,
        dados: motorista
      });

      console.log(`✅ MOTORISTA ONLINE: ${motorista.nome} | Total: ${motoristasOnline.size}`);

    } catch (e) { console.log("Erro ao ficar online", e) }
  });

  // 🔴 MOTORISTA FICOU OFFLINE / DESCONECTOU
  const desconectar = async () => {
    for (const [id, dados] of motoristasOnline){
      if(dados.socketId === socket.id){
        await Usuario.findByIdAndUpdate(id, {online: false});
        motoristasOnline.delete(id);
        console.log(`❌ MOTORISTA OFFLINE | Total: ${motoristasOnline.size}`);
        break;
      }
    }
  };
  socket.on('offline', desconectar);
  socket.on('disconnect', desconectar);

  // 🆕 PASSAGEIRO PEDE CORRIDA 🏍️📲
  socket.on('nova_corrida', async (dadosCorrida) => {
    console.log("🚕 NOVA CORRIDA SOLICITADA!", dadosCorrida);

    // 📝 SALVAR CORRIDA NO BANCO
    const corrida = new Corrida({
      origem: dadosCorrida.origem,
      destino: dadosCorrida.destino,
      distancia: dadosCorrida.distancia,
      valor: dadosCorrida.valor,
      passageiro: dadosCorrida.passageiroId,
      nomePassageiro: dadosCorrida.passageiroNome,
      telPassageiro: dadosCorrida.telefone
    });
    await corrida.save();

    // 📤 ENVIAR PARA TODOS MOTORISTAS ONLINE (Broadcast) 📡📢
    if(motoristasOnline.size > 0){
      motoristasOnline.forEach(m => {
        io.to(m.socketId).emit('nova_corrida', {
          id: corrida._id,
          origem: corrida.origem,
          destino: corrida.destino,
          distancia: corrida.distancia,
          valor: corrida.valor,
          passageiroNome: corrida.nomePassageiro,
          telefone: corrida.telPassageiro,
          passageiroId: corrida.passageiro
        });
      });
    } else {
      // 🚫 Nenhum motorista disponível
      socket.emit('corrida_cancelada', "Nenhum motorista disponível no momento 😔");
    }
  });

  // ✅ MOTORISTA ACEITOU CORRIDA 🤝✅
  socket.on('aceitar_corrida', async (dados) => {
    const corrida = await Corrida.findById(dados.corridaId);
    if(!corrida || corrida.status !== 'aguardando') return;

    // 🔄 ATUALIZAR STATUS
    corrida.status = 'aceita';
    corrida.motorista = dados.motorista._id;
    corrida.nomeMotorista = dados.motorista.nome;
    await corrida.save();

    // 📊 ATUALIZAR ESTATISTICAS
    await Usuario.findByIdAndUpdate(dados.motorista._id, {$inc: {"estatisticas.totalCorridas": 1, "estatisticas.ganhoTotal": corrida.valor}});
    await Usuario.findByIdAndUpdate(corrida.passageiro, {$inc: {"estatisticas.totalCorridas": 1, "estatisticas.valorGasto": corrida.valor}});

    // 🔍 AVISAR PASSAGEIRO QUE MOTORISTA ACHOUU!! 🎉🚗
    io.to(socket.id).emit('motorista_na_corrida', 'ok'); // Confirma pro motorista
    socket.broadcast.emit('motorista_encontrado', { // Manda pro passageiro
      corridaId: corrida._id,
      nome: dados.motorista.nome,
      foto: dados.motorista.foto,
      marca: dados.motorista.marca,
      cor: dados.motorista.cor,
      placa: dados.motorista.placa,
      nota: dados.motorista.avaliacoes.length ? (dados.motorista.avaliacoes.reduce((a,b)=>a+b.nota,0)/dados.motorista.avaliacoes.length).toFixed(1) : '5.0'
    });
  });

  // ❌ MOTORISTA RECUSOU
  socket.on('recusar_corrida', (id) => {
    // Aqui poderíamos enviar para o próximo motorista, mas vamos manter simples por enquanto 🫶
    console.log("❌ Corrida recusada:", id);
  });

  // 📍 LOCALIZAÇÃO MOTORISTA EM TEMPO REAL 🗺️📍⚡
  socket.on('local_motorista', async (dadosLocal) => {
    // 🔍 BUSCA A CORRIDA PARA PEGAR O ID DO PASSAGEIRO E ENVIAR PRA ELE
    const corrida = await Corrida.findById(dadosLocal.corridaId).populate('passageiro');
    if(!corrida || corrida.status !== 'aceita') return;

    // 💾 ATUALIZA LOCAL NO MOTORISTA
    for (const [id, m] of motoristasOnline){
      if(m.socketId === socket.id){
        m.dados.localizacao = {lat: dadosLocal.lat, lng: dadosLocal.lng};
        await Usuario.findByIdAndUpdate(id, {localizacao: {lat: dadosLocal.lat, lng: dadosLocal.lng}});
        break;
      }
    }

    // 📡 ENVIA COORDENADAS PARA O PASSAGEIRO VER NO MAPA!!! 🗺️🏃💨
    socket.broadcast.emit('motorista_local', {lat: dadosLocal.lat, lng: dadosLocal.lng});
  });

  // 🏁 FINALIZAR CORRIDA ✅🏁💰
  socket.on('finalizar_corrida', async (idCorrida) => {
    const corrida = await Corrida.findById(idCorrida);
    if(!corrida) return;
    corrida.status = 'finalizada';
    await corrida.save();

    // 📢 AVISAR PASSAGEIRO PRA AVALIAR! ⭐📨
    io.emit('corrida_finalizada');
  });

  // 🚫 CANCELAR CORRIDA
  socket.on('cancelar_corrida', async (idCorrida) => {
    await Corrida.findByIdAndUpdate(idCorrida, {status: 'cancelada'});
    io.emit('corrida_cancelada', "Usuário cancelou a corrida 🛑");
  });

});

// 🏃💨 SUBIR SERVIDOR
const PORTA = process.env.PORTA || 3000;
servidor.listen(PORTA, () => {
  console.log(`🚀🚀 BACKEND RODANDO NA PORTA ${PORTA} 🚀🟢🔥`);
  console.log(`🔗 URL: http://localhost:${PORTA}`);
});
