<template>
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
