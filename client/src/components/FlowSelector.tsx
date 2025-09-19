import React from 'react';
import { OAuthFlow } from '../../../shared/types';

interface FlowSelectorProps {
  selectedFlow: OAuthFlow;
  onFlowChange: (flow: OAuthFlow) => void;
}

const FlowSelector: React.FC<FlowSelectorProps> = ({ selectedFlow, onFlowChange }) => {
  const flows = [
    {
      id: 'authorization_code' as OAuthFlow,
      name: 'Authorization Code',
      description: 'Fluxo tradicional para aplicações web com backend seguro'
    },
    {
      id: 'pkce' as OAuthFlow,
      name: 'PKCE',
      description: 'Authorization Code com PKCE para SPAs e apps móveis'
    },
    {
      id: 'client_credentials' as OAuthFlow,
      name: 'Client Credentials',
      description: 'Autenticação direta servidor-para-servidor'
    }
  ];

  return (
    <div className="flow-selector">
      <h3>Escolha um Fluxo OAuth</h3>
      <div className="flow-options">
        {flows.map(flow => (
          <div 
            key={flow.id}
            className={`flow-option ${selectedFlow === flow.id ? 'selected' : ''}`}
            onClick={() => onFlowChange(flow.id)}
          >
            <h4>{flow.name}</h4>
            <p>{flow.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default FlowSelector;
