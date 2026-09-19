import React, { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import './FAQ.css';

export default function FAQ() {
  const [openIndex, setOpenIndex] = useState(0);

  const faqs = [
    {
      q: "Is BehindTheLink free?",
      a: "v0.1.0 is free."
    },
    {
      q: "Does it require an account?",
      a: "No."
    },
    {
      q: "Does it require the Chrome Web Store?",
      a: "No. v0.1.0 is distributed directly through GitHub Releases."
    },
    {
      q: "Does BehindTheLink guarantee that a website is safe?",
      a: "No. It provides observable link and context information but cannot guarantee the safety of a website."
    },
    {
      q: "What happens if the destination cannot be verified?",
      a: "BehindTheLink tells you that it could not verify the destination."
    },
    {
      q: "Does it send my browsing history to a BehindTheLink server?",
      a: "No BehindTheLink backend is used to store browsing history in v0.1.0."
    }
  ];

  return (
    <section id="faq" className="section">
      <div className="container">
        <div className="section-header">
          <h2>Frequently Asked Questions</h2>
        </div>
        
        <div className="faq-container">
          {faqs.map((faq, idx) => (
            <div 
              key={idx} 
              className={`faq-item ${openIndex === idx ? 'active' : ''}`}
              onClick={() => setOpenIndex(openIndex === idx ? -1 : idx)}
            >
              <div className="faq-question">
                <span>{faq.q}</span>
                {openIndex === idx ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
              </div>
              <div className="faq-answer">
                <div className="faq-answer-content">{faq.a}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
