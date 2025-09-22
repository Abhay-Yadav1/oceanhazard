function logout() {
    // Clear session data
    sessionStorage.clear();
    localStorage.removeItem('currentUser');
    
    // Redirect to login page
    window.location.href = 'Login.html';
}