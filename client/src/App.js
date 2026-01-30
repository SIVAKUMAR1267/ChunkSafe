import React, { useState } from 'react';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import './App.css';

function App() {
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [user, setUser] = useState(localStorage.getItem('username') || '');
  const [view, setView] = useState('login'); 

  const logout = () => {
    localStorage.clear();
    setToken('');
    setUser('');
    setView('login');
  };

  if (token) {
    return <Dashboard token={token} user={user} logout={logout} />;
  }

  return (
    <div className="app-wrapper">
      {view === 'login' ? (
        <Login setToken={setToken} setUser={setUser} setView={setView} />
      ) : (
        <Register setView={setView} />
      )}
    </div>
  );
}

export default App;