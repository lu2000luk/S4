"use client";

import { Canvas } from "@react-three/fiber";
import { Text3D, Center, shaderMaterial, Bounds } from "@react-three/drei";
import { useFrame } from "@react-three/fiber";
import { useRef, useMemo, useEffect } from "react";
import * as THREE from "three";

const ASCIIMaterial = shaderMaterial(
  {
    uTime: 0,
    uResolution: new THREE.Vector2(800, 600),
    uCharSize: 8.0,
    uLightPos: new THREE.Vector3(5, 5, 5),
    uLightColor: new THREE.Color(1, 1, 1),
    uAmbient: 0.2,
  },
  // Vertex Shader - by claude
  `
    varying vec3 vNormal;
    varying vec3 vPosition;
    varying vec2 vUv;

    void main() {
      vNormal = normalize(normalMatrix * normal);
      vPosition = (modelViewMatrix * vec4(position, 1.0)).xyz;
      vUv = uv;
      gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
    }
  `,
  // Fragment Shader - by claude
  `
    uniform float uTime;
    uniform vec2 uResolution;
    uniform float uCharSize;
    uniform vec3 uLightPos;
    uniform vec3 uLightColor;
    uniform float uAmbient;

    varying vec3 vNormal;
    varying vec3 vPosition;
    varying vec2 vUv;

    float character(int n, vec2 p) {
      p = floor(p * vec2(4.0, -4.0) + 2.5);
      if (clamp(p.x, 0.0, 4.0) == p.x) {
        if (clamp(p.y, 0.0, 4.0) == p.y) {
          int a = int(round(p.x) + 5.0 * round(p.y));
          if (((n >> a) & 1) == 1) return 1.0;
        }
      }
      return 0.0;
    }

    void main() {
      vec3 normal = normalize(vNormal);
      vec3 lightDir = normalize(uLightPos - vPosition);
      float diff = max(dot(normal, lightDir), 0.0);

      vec3 viewDir = normalize(-vPosition);
      vec3 reflectDir = reflect(-lightDir, normal);
      float spec = pow(max(dot(viewDir, reflectDir), 0.0), 32.0);

      float brightness = uAmbient + diff * 0.7 + spec * 0.3;
      brightness = clamp(brightness, 0.0, 1.0);

      vec2 pixelPos = gl_FragCoord.xy;
      vec2 charCoord = mod(pixelPos, uCharSize) / uCharSize;

      int charIndex;
      if (brightness < 0.125) charIndex = 0;
      else if (brightness < 0.25) charIndex = 46; // .
      else if (brightness < 0.375) charIndex = 58; // :
      else if (brightness < 0.5) charIndex = 45; // -
      else if (brightness < 0.625) charIndex = 61; // =
      else if (brightness < 0.75) charIndex = 43; // +
      else if (brightness < 0.875) charIndex = 42; // *
      else charIndex = 35; // #

      int chars[9];
      chars[0] = 0;           // space
      chars[1] = 65536;       // .
      chars[2] = 1040448;     // :
      chars[3] = 1040;        // -
      chars[4] = 1082401;     // =
      chars[5] = 1076768;     // +
      chars[6] = 1082914;     // *
      chars[7] = 2031647;     // #
      chars[8] = 2031647;     // fallback

      int index = int(brightness * 8.0);
      index = clamp(index, 0, 8);

      float charPixel = character(chars[index], charCoord);

      // Apply color
      vec3 asciiColor = uLightColor * brightness;
      vec3 finalColor = mix(vec3(0.0), asciiColor, charPixel);

      // Add slight green tint for classic terminal look
      finalColor = mix(finalColor, vec3(0.0, finalColor.g * 1.2, 0.0), 0.3);

      gl_FragColor = vec4(finalColor, 1.0);
    }
  `,
);

function AnimatedS4Text() {
  const groupRef = useRef<THREE.Group>(null);
  const materialRef = useRef<any>(null);

  useFrame((state) => {
    if (groupRef.current) {
      groupRef.current.rotation.y = state.clock.elapsedTime * 0.6;
      groupRef.current.rotation.z =
        Math.sin(state.clock.elapsedTime * 0.5) * 0.2;
    }

    if (materialRef.current) {
      materialRef.current.uTime = state.clock.elapsedTime;

      const t = state.clock.elapsedTime;
      materialRef.current.uLightPos.set(
        Math.cos(t) * 5,
        Math.sin(t * 0.5) * 3 + 3,
        Math.sin(t) * 5,
      );
    }
  });

  const material = useMemo(() => {
    const mat = new ASCIIMaterial();
    mat.uResolution.set(window.innerWidth, window.innerHeight);
    return mat;
  }, []);

  useEffect(() => {
    const onResize = () => {
      if (materialRef.current) {
        materialRef.current.uResolution.set(
          window.innerWidth,
          window.innerHeight,
        );
      }
    };

    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  return (
    <group ref={groupRef}>
      <Bounds fit clip observe margin={1.2}>
        <Center>
          <Text3D
            font={"/lexend.json"}
            size={1.5}
            height={0.3}
            curveSegments={12}
            bevelEnabled
            bevelThickness={0.08}
            bevelSize={0.08}
            bevelOffset={0}
            bevelSegments={10}
          >
            S4
            <primitive object={material} ref={materialRef} attach="material" />
          </Text3D>
        </Center>
      </Bounds>
    </group>
  );
}

export function S4C() {
  return (
    <Canvas camera={{ position: [0, 0, 5], fov: 50 }} shadows>
      <ambientLight intensity={3} />
      <directionalLight position={[5, 5, 5]} intensity={4} castShadow />
      <directionalLight position={[-5, 5, 5]} intensity={3} />
      <directionalLight position={[0, -3, 5]} intensity={2} />
      <pointLight position={[0, 0, 8]} intensity={5} />
      <AnimatedS4Text />
    </Canvas>
  );
}
