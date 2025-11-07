import { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';

export function OAuthSuccessPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const provider = searchParams.get('provider') || 'provider';

  useEffect(() => {
    // Notify parent window if opened in popup
    if (window.opener) {
      window.opener.postMessage({ type: 'oauth-success', provider }, '*');
    }

    // Auto-redirect after 3 seconds
    const timeout = setTimeout(() => {
      if (window.opener) {
        window.close();
      } else {
        navigate('/oauth');
      }
    }, 3000);

    return () => clearTimeout(timeout);
  }, [provider, navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-500 to-purple-700">
      <div className="bg-white rounded-lg shadow-xl p-8 max-w-md w-full mx-4">
        {/* Success Icon */}
        <div className="flex justify-center mb-6">
          <div className="rounded-full bg-green-100 p-4">
            <svg
              className="h-16 w-16 text-green-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M5 13l4 4L19 7"
              />
            </svg>
          </div>
        </div>

        {/* Success Message */}
        <h1 className="text-2xl font-bold text-center text-gray-900 mb-2">
          Connection Successful!
        </h1>
        <p className="text-center text-gray-600 mb-6">
          You've successfully connected to <span className="font-semibold">{provider}</span>
        </p>

        {/* Instructions */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
          <p className="text-sm text-blue-800">
            {window.opener
              ? 'This window will close automatically...'
              : 'You can now use this provider in your workflows.'}
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex gap-3">
          {window.opener ? (
            <button
              onClick={() => window.close()}
              className="flex-1 px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors font-medium"
            >
              Close Window
            </button>
          ) : (
            <>
              <button
                onClick={() => navigate('/oauth')}
                className="flex-1 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors font-medium"
              >
                View Integrations
              </button>
              <button
                onClick={() => navigate('/')}
                className="flex-1 px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors font-medium"
              >
                Go to Dashboard
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
