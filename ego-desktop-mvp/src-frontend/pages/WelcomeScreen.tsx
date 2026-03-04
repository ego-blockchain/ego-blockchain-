import React from 'react';

const WelcomeScreen: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-ego-blue mb-4">Welcome to Ego Desktop</h1>
        <p className="text-xl text-gray-300 mb-8">Quantum-Safe Blockchain Demo</p>
        <button className="bg-ego-blue hover:bg-blue-600 px-6 py-3 rounded-lg font-semibold">
          Get Started
        </button>
      </div>
    </div>
  );
};

export default WelcomeScreen;