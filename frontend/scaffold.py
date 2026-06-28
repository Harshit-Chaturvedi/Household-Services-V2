import os

def create_file(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

# src/main.js
create_file('src/main.js', '''import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import 'bootstrap/dist/css/bootstrap.min.css'
import 'bootstrap'
import './assets/main.css'

const app = createApp(App)
app.use(router)
app.mount('#app')
''')

# src/App.vue
create_file('src/App.vue', '''<template>
  <div id="app">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
      <div class="container-fluid">
        <a class="navbar-brand" href="#">Household Services</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav me-auto">
            <li class="nav-item">
              <router-link class="nav-link" to="/">Home</router-link>
            </li>
          </ul>
          <ul class="navbar-nav">
            <li class="nav-item" v-if="!isLoggedIn">
              <router-link class="nav-link" to="/login">Login</router-link>
            </li>
            <li class="nav-item" v-if="isLoggedIn">
              <a class="nav-link" href="#" @click="logout">Logout</a>
            </li>
          </ul>
        </div>
      </div>
    </nav>
    <div class="container mt-4">
      <router-view/>
    </div>
  </div>
</template>

<script>
export default {
  name: 'App',
  computed: {
    isLoggedIn() {
      return !!localStorage.getItem('access_token');
    }
  },
  methods: {
    logout() {
      localStorage.removeItem('access_token');
      localStorage.removeItem('role');
      this.$router.push('/login');
    }
  }
}
</script>
''')

# src/router/index.js
create_file('src/router/index.js', '''import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'
import LoginView from '../views/LoginView.vue'

const routes = [
  { path: '/', name: 'home', component: HomeView },
  { path: '/login', name: 'login', component: LoginView }
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

export default router
''')

# src/views/HomeView.vue
create_file('src/views/HomeView.vue', '''<template>
  <div class="home">
    <div class="p-5 mb-4 bg-light rounded-3 text-center hero-section">
      <div class="container-fluid py-5">
        <h1 class="display-5 fw-bold text-primary">Welcome to Household Services V2</h1>
        <p class="col-md-8 mx-auto fs-4">
          Book trusted professionals for all your home needs. Quick, reliable, and secure!
        </p>
        <router-link to="/login" class="btn btn-primary btn-lg mt-3 shadow-sm">Get Started</router-link>
      </div>
    </div>
  </div>
</template>
<style scoped>
.hero-section {
    background: linear-gradient(135deg, #e0f7fa 0%, #ffffff 100%);
    box-shadow: 0 4px 15px rgba(0,0,0,0.05);
}
</style>
''')

# src/views/LoginView.vue
create_file('src/views/LoginView.vue', '''<template>
  <div class="login row justify-content-center">
    <div class="col-md-6">
      <div class="card shadow-lg border-0 rounded-lg mt-5">
        <div class="card-header bg-primary text-white text-center">
          <h3 class="font-weight-light my-2">Login</h3>
        </div>
        <div class="card-body">
          <form @submit.prevent="handleLogin">
            <div class="form-floating mb-3">
              <input class="form-control" id="inputEmail" type="email" placeholder="name@example.com" v-model="email" required />
              <label for="inputEmail">Email address</label>
            </div>
            <div class="form-floating mb-3">
              <input class="form-control" id="inputPassword" type="password" placeholder="Password" v-model="password" required />
              <label for="inputPassword">Password</label>
            </div>
            <div class="d-flex align-items-center justify-content-between mt-4 mb-0">
              <button class="btn btn-primary w-100 py-2" type="submit">Login</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>
<script>
import axios from 'axios';
export default {
  data() { return { email: '', password: '' }; },
  methods: {
    async handleLogin() {
      try {
        const res = await axios.post('http://localhost:5000/login', {
          email: this.email,
          password: this.password
        });
        localStorage.setItem('access_token', res.data.access_token);
        localStorage.setItem('role', res.data.role);
        this.$router.push('/');
      } catch (err) {
        alert(err.response?.data?.message || 'Login failed');
      }
    }
  }
}
</script>
''')

os.makedirs('src/assets', exist_ok=True)
create_file('src/assets/main.css', '''
body {
    font-family: 'Inter', sans-serif;
    background-color: #f8f9fa;
    color: #212529;
}
.navbar {
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}
.card {
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}
.card:hover {
    transform: translateY(-5px);
    box-shadow: 0 10px 20px rgba(0,0,0,0.1) !important;
}
.btn-primary {
    background-color: #0069d9;
    border: none;
    transition: background-color 0.3s ease;
}
.btn-primary:hover {
    background-color: #0056b3;
}
''')

print("Scaffold complete.")
