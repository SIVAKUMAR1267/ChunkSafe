import React, { useState } from 'react';
import axios from 'axios';

const Register = ({ setView }) => {
  const [formData, setFormData] = useState({ username: '', password: '' });

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      await axios.post('http://localhost:5000/register', formData);
      alert('Registration successful! Please login.');
      setView('login');
    } catch (err) {
      alert('Registration Failed');
    }
  };

  return (
    <div className="container">
      <h2>Register</h2>
      <form onSubmit={handleRegister}>
        <input 
          type="text" placeholder="Username" required
          onChange={(e) => setFormData({...formData, username: e.target.value})} 
        />
        <input 
          type="password" placeholder="Password" required
          onChange={(e) => setFormData({...formData, password: e.target.value})} 
        />
        <button type="submit">Register</button>
      </form>
      <p onClick={() => setView('login')} className="link">Have an account? Login</p>
    </div>
  );
};

export default Register;