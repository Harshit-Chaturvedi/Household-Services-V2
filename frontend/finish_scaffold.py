import os

def create_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

# Update Router
create_file('src/router/index.js', '''import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'
import LoginView from '../views/LoginView.vue'
import CustomerDashboard from '../views/CustomerDashboard.vue'
import AdminDashboard from '../views/AdminDashboard.vue'
import ProfessionalDashboard from '../views/ProfessionalDashboard.vue'

const routes = [
  { path: '/', name: 'home', component: HomeView },
  { path: '/login', name: 'login', component: LoginView },
  { path: '/customer', name: 'customer-dashboard', component: CustomerDashboard },
  { path: '/admin', name: 'admin-dashboard', component: AdminDashboard },
  { path: '/professional', name: 'professional-dashboard', component: ProfessionalDashboard }
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

export default router
''')

# Customer Dashboard
create_file('src/views/CustomerDashboard.vue', '''<template>
  <div class="customer-dashboard">
    <h2 class="mb-4">Customer Dashboard</h2>
    <div class="row">
      <div class="col-md-4 mb-4" v-for="service in services" :key="service.id">
        <div class="card h-100 shadow-sm border-0">
          <div class="card-body">
            <h5 class="card-title text-primary">{{ service.name }}</h5>
            <p class="card-text text-muted">{{ service.description || 'Professional service for your home.' }}</p>
            <button class="btn btn-outline-primary mt-auto" @click="requestService(service.id)">Request Service</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
<script>
import axios from 'axios';
export default {
  data() { return { services: [] }; },
  async created() {
    try {
      const apiUrl = process.env.VUE_APP_API_URL || 'http://localhost:5000';
      const res = await axios.get(`${apiUrl}/services`);
      this.services = res.data;
    } catch(err) { console.error(err); }
  },
  methods: {
    requestService(id) { alert('Service requested (ID: ' + id + ')'); }
  }
}
</script>
''')

# Admin Dashboard
create_file('src/views/AdminDashboard.vue', '''<template>
  <div class="admin-dashboard">
    <h2 class="mb-4">Admin Dashboard</h2>
    <div class="card shadow-sm border-0">
      <div class="card-body text-center p-5">
        <h4 class="text-secondary">Admin Controls</h4>
        <p>Manage services, approve professionals, and monitor activities.</p>
        <button class="btn btn-primary me-2">Manage Services</button>
        <button class="btn btn-success">View Professionals</button>
      </div>
    </div>
  </div>
</template>
''')

# Professional Dashboard
create_file('src/views/ProfessionalDashboard.vue', '''<template>
  <div class="professional-dashboard">
    <h2 class="mb-4">Professional Dashboard</h2>
    <div class="card shadow-sm border-0">
      <div class="card-body text-center p-5">
        <h4 class="text-secondary">Your Pending Requests</h4>
        <p>No new requests available at the moment.</p>
      </div>
    </div>
  </div>
</template>
''')

print("All dashboards generated successfully.")
