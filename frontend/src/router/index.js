import { createRouter, createWebHistory } from 'vue-router'
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
