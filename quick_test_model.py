"""
Quick test script to create a mock trained model for testing the web application
"""
import joblib
from sklearn.neural_network import MLPClassifier
import numpy as np
import os

# Create trained_models directory if it doesn't exist
os.makedirs('trained_models', exist_ok=True)

# Create and train a simple MLP model
print("Creating mock MLP model for testing...")
model = MLPClassifier(hidden_layer_sizes=(100,), max_iter=100, random_state=42)

# Create dummy training data (28 features, 5 classes matching our config)
X_dummy = np.random.rand(500, 28)
y_dummy = np.random.randint(0, 5, 500)

# Train the model
model.fit(X_dummy, y_dummy)

# Save the model
model_path = 'trained_models/mlp_model.pkl'
joblib.dump(model, model_path)

print(f"✅ Mock model saved to: {model_path}")
print(f"   - Model score on dummy data: {model.score(X_dummy, y_dummy):.3f}")
print("\n✅ You can now test the web application!")
print("   Run: python app.py")
print("   Then visit: http://localhost:5000")
