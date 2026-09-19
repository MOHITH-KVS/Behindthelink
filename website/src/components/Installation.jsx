import React from 'react';
import { Download, FolderOpen, Settings, Code, FileCode2, Pin, Play } from 'lucide-react';
import { DOWNLOAD_URL } from '../config';
import './Installation.css';

export default function Installation() {
  const steps = [
    {
      num: 1,
      title: "Download the ZIP",
      desc: "Click Download for Chrome to download the BehindTheLink ZIP from GitHub.",
      icon: <Download size={24} />,
      action: (
        <a href={DOWNLOAD_URL} className="btn btn-primary btn-small mt-3">
          Download for Chrome
        </a>
      )
    },
    {
      num: 2,
      title: "Extract the ZIP",
      desc: "Open your Downloads folder, right-click the ZIP, and choose Extract All.",
      icon: <FolderOpen size={24} />,
      visual: (
        <div className="install-visual">
          <div className="visual-file">BehindTheLink-v0.1.0.zip</div>
          <div className="visual-arrow">&darr;</div>
          <div className="visual-file bg-accent text-white">Extract All</div>
          <div className="visual-arrow">&darr;</div>
          <div className="visual-file folder">BehindTheLink-v0.1.0/</div>
        </div>
      )
    },
    {
      num: 3,
      title: "Open Chrome Extensions",
      desc: "Open Chrome and enter chrome://extensions in the address bar.",
      icon: <Settings size={24} />,
      visual: (
        <div className="install-visual">
          <div className="visual-url-bar">chrome://extensions</div>
        </div>
      )
    },
    {
      num: 4,
      title: "Enable Developer Mode",
      desc: "Turn on Developer mode in the top-right corner.",
      icon: <Code size={24} />,
      visual: (
        <div className="install-visual">
          <div className="toggle-switch active">
            <span>Developer mode</span>
            <div className="toggle-knob"></div>
          </div>
        </div>
      )
    },
    {
      num: 5,
      title: "Load Unpacked",
      desc: "Click Load unpacked and select the extracted BehindTheLink-v0.1.0 folder.",
      icon: <FileCode2 size={24} />,
      visual: (
        <div className="install-visual">
          <div className="visual-file btn-outline-style">Load unpacked</div>
          <div className="visual-arrow">&darr;</div>
          <div className="visual-file folder">BehindTheLink-v0.1.0</div>
        </div>
      )
    },
    {
      num: 6,
      title: "Pin BehindTheLink",
      desc: "Click the Extensions puzzle icon and pin BehindTheLink for easy access.",
      icon: <Pin size={24} />
    },
    {
      num: 7,
      title: "Start using it",
      desc: "Open any webpage and hover over a link.",
      icon: <Play size={24} />
    }
  ];

  return (
    <section id="installation" className="section">
      <div className="container">
        <div className="section-header">
          <h2>Get BehindTheLink running in a few minutes.</h2>
          <p>
            No Chrome Web Store required. Download the ZIP, load it into Chrome, and start hovering over links.
          </p>
        </div>
        
        <div className="install-steps">
          {steps.map((step, idx) => (
            <div key={idx} className="install-step-card">
              <div className="install-step-header">
                <div className="install-step-num">{step.num}</div>
                <div className="install-step-icon">{step.icon}</div>
                <h3 className="install-step-title">{step.title}</h3>
              </div>
              <div className="install-step-body">
                <p className="install-step-desc">{step.desc}</p>
                {step.action && step.action}
                {step.visual && step.visual}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
