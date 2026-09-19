import React from 'react';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import Problem from './components/Problem';
import HowItWorks from './components/HowItWorks';
import Features from './components/Features';
import SeeItInAction from './components/SeeItInAction';
import Installation from './components/Installation';
import HowToUse from './components/HowToUse';
import Privacy from './components/Privacy';
import Limitations from './components/Limitations';
import FAQ from './components/FAQ';
import OpenSource from './components/OpenSource';
import Footer from './components/Footer';

function App() {
  return (
    <div className="app">
      <Navbar />
      <main>
        <Hero />
        <Problem />
        <HowItWorks />
        <Features />
        <SeeItInAction />
        <Installation />
        <HowToUse />
        <Privacy />
        <Limitations />
        <FAQ />
        <OpenSource />
      </main>
      <Footer />
    </div>
  );
}

export default App;
