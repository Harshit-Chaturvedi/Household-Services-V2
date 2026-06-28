<template>
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
