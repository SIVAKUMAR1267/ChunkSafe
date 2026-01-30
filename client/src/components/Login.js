import React, { useState } from 'react';
import axios from 'axios';

const Login = ({ setToken, setUser, setView }) => {
  const [formData, setFormData] = useState({ username: '', password: '' });

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post('http://localhost:5000/login', formData);
      localStorage.setItem('token', res.data.token);
      localStorage.setItem('username', res.data.username);
      setToken(res.data.token);
      setUser(res.data.username);
    } catch (err) {
      alert(err.response?.data?.error || 'Login Failed');
    }
  };

  return (
    <div className="container">
      <h2>Login</h2>
      <form onSubmit={handleLogin}>
        <input 
          type="text" placeholder="Username" required
          onChange={(e) => setFormData({...formData, username: e.target.value})} 
        />
        <input 
          type="password" placeholder="Password" required
          onChange={(e) => setFormData({...formData, password: e.target.value})} 
        />
        <button type="submit">Login</button>
      </form>
      <p onClick={() => setView('register')} className="link">Need an account? Register</p>
    </div>
  );
};

export default Login;