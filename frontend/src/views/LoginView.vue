<template>
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
        const apiUrl = process.env.VUE_APP_API_URL || 'http://localhost:5000';
        const res = await axios.post(`${apiUrl}/login`, {
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
