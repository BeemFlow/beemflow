import { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';

/**
 * OAuth Success Page
 *
 * Displayed after successful OAuth connection to close the popup and notify parent window.
 *
 * Flow:
 * 1. OAuth provider redirects to backend: /oauth/callback?code=...
 * 2. Backend validates, exchanges code, saves credentials
 * 3. Backend redirects to: /oauth/success?provider=google
 * 4. This component loads (via React Router)
 * 5. Sends postMessage to parent window
 * 6. Auto-closes popup after 1.5 seconds
 *
 * Works in both deployment modes:
 * - Integrated: Backend serves index.html → React Router → this component
 * - Separate: Vite/CDN serves index.html → React Router → this component
 */
export function OAuthSuccessPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const provider = searchParams.get('provider') || 'provider';

  useEffect(() => {
    // Notify parent window if opened in popup
    if (window.opener) {
      try {
        // SECURITY: Use specific origin, not wildcard (prevents malicious sites from receiving OAuth events)
        // In integrated mode: same origin as this page
        // In separate mode: parent and popup are both on frontend origin
        const targetOrigin = window.location.origin;

        window.opener.postMessage(
          { type: 'oauth-success', provider },
          targetOrigin  // Specific origin instead of '*' for security
        );
      } catch (e) {
        console.error('Failed to notify parent window:', e);
      }
    }

    // Auto-close popup or redirect after delay
    const timeout = setTimeout(() => {
      if (window.opener) {
        // Popup mode: close window
        window.close();
      } else {
        // Direct navigation mode: redirect back to OAuth page
        navigate('/oauth');
      }
    }, 1500);

    return () => clearTimeout(timeout);
  }, [provider, navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-500 to-purple-700">
      <div className="bg-white rounded-lg shadow-xl p-8 max-w-md w-full mx-4 text-center">
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
        <h1 className="text-2xl font-bold text-gray-900 mb-2">
          Connection Successful!
        </h1>
        <p className="text-gray-600 mb-6">
          You've successfully connected to{' '}
          <span className="font-semibold text-purple-600">{provider}</span>
        </p>

        {/* Status Message */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <p className="text-sm text-blue-800">
            {window.opener
              ? 'This window will close automatically...'
              : 'Redirecting back to OAuth providers...'}
          </p>
        </div>
      </div>
    </div>
  );
}
