"use client";

import { S4C } from "@/components/s4c";
import { Download, Github } from "lucide-react";
import {
  AnimatePresence,
  motion,
  useMotionValue,
  useSpring,
} from "motion/react";
import { useEffect, useMemo, useRef, useState } from "react";

function Loading() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="1em"
      height="1em"
      viewBox="0 0 24 24"
    >
      <g stroke="currentColor">
        <circle
          cx="12"
          cy="12"
          r="9.5"
          fill="none"
          strokeLinecap="round"
          strokeWidth="3"
        >
          <animate
            attributeName="stroke-dasharray"
            calcMode="spline"
            dur="1.5s"
            keySplines="0.42,0,0.58,1;0.42,0,0.58,1;0.42,0,0.58,1"
            keyTimes="0;0.475;0.95;1"
            repeatCount="indefinite"
            values="0 150;42 150;42 150;42 150"
          />
          <animate
            attributeName="stroke-dashoffset"
            calcMode="spline"
            dur="1.5s"
            keySplines="0.42,0,0.58,1;0.42,0,0.58,1;0.42,0,0.58,1"
            keyTimes="0;0.475;0.95;1"
            repeatCount="indefinite"
            values="0;-16;-59;-59"
          />
        </circle>
        <animateTransform
          attributeName="transform"
          dur="2s"
          repeatCount="indefinite"
          type="rotate"
          values="0 12 12;360 12 12"
        />
      </g>
    </svg>
  );
}

export default function Page() {
  const [sourceClicked, setSourceClicked] = useState(false);

  const cursorX = useMotionValue(-100);
  const cursorY = useMotionValue(-100);
  const cursorWidth = useMotionValue(20);
  const cursorHeight = useMotionValue(20);
  const cursorRadius = useMotionValue("9999px");
  const cursorScale = useMotionValue(1);

  const springConfig = { damping: 30, stiffness: 400, mass: 0.3 };
  const springX = useSpring(cursorX, springConfig);
  const springY = useSpring(cursorY, springConfig);
  const springWidth = useSpring(cursorWidth, { ...springConfig, mass: 0.35 });
  const springHeight = useSpring(cursorHeight, { ...springConfig, mass: 0.35 });
  const springScale = useSpring(cursorScale, {
    ...springConfig,
    duration: 0.1,
  });

  const mousePos = useRef({ x: -100, y: -100 });
  const hoveredEl = useRef<HTMLElement | null>(null);

  const BORDER_W = 2;
  const BORDER_PAD = 4;
  const wrapOffset = BORDER_PAD + BORDER_W / 2;

  useEffect(() => {
    const handleMove = (e: MouseEvent) => {
      mousePos.current = { x: e.clientX, y: e.clientY };
    };

    const handleD = () => {
      if (!hoveredEl.current) {
        cursorScale.set(0.8);
      }
    };

    const handleU = () => {
      if (!hoveredEl.current) {
        cursorScale.set(1);
      }
    };

    const getWrapEl = (t: EventTarget | null) =>
      t instanceof Element
        ? (t.closest(".cursor-wrap-around") as HTMLElement | null)
        : null;

    const handleOver = (e: PointerEvent) => {
      const el = getWrapEl(e.target);
      if (el) {
        hoveredEl.current = el;
        cursorScale.set(1);
      }
    };

    const handleOut = (e: PointerEvent) => {
      const from = getWrapEl(e.target);
      if (!from) return;

      const to = getWrapEl(e.relatedTarget);
      if (to) {
        hoveredEl.current = to;
        return;
      }

      hoveredEl.current = null;
    };

    window.addEventListener("mousemove", handleMove, { passive: true });
    window.addEventListener("mousedown", handleD);
    window.addEventListener("mouseup", handleU);

    window.addEventListener("pointerover", handleOver);
    window.addEventListener("pointerout", handleOut);

    return () => {
      window.removeEventListener("mousemove", handleMove);
      window.removeEventListener("mousedown", handleD);
      window.removeEventListener("mouseup", handleU);

      window.removeEventListener("pointerover", handleOver);
      window.removeEventListener("pointerout", handleOut);
    };
  }, [cursorScale]);

  useEffect(() => {
    let frameId: number;

    const updateCursor = () => {
      const el = hoveredEl.current;

      if (el) {
        const rect = el.getBoundingClientRect();
        const cs = window.getComputedStyle(el);
        const radius = cs.borderRadius || "9999px";

        cursorX.set(rect.left - wrapOffset);
        cursorY.set(rect.top - wrapOffset);
        cursorWidth.set(rect.width + wrapOffset * 2);
        cursorHeight.set(rect.height + wrapOffset * 2);
        cursorRadius.set(radius);
      } else {
        const { x, y } = mousePos.current;
        cursorX.set(x - 10);
        cursorY.set(y - 10);
        cursorWidth.set(20);
        cursorHeight.set(20);
        cursorRadius.set("9999px");
      }

      frameId = requestAnimationFrame(updateCursor);
    };

    frameId = requestAnimationFrame(updateCursor);
    return () => cancelAnimationFrame(frameId);
  }, [cursorHeight, cursorRadius, cursorWidth, cursorX, cursorY, wrapOffset]);

  return (
    <>
      <div className="w-screen h-screen">
        <S4C />

        <motion.div
          aria-hidden="true"
          className="fixed top-0 left-0 border-2 border-white/80 pointer-events-none z-9999 mix-blend-difference"
          style={{
            x: springX,
            y: springY,
            width: springWidth,
            height: springHeight,
            borderRadius: cursorRadius,
            scale: springScale,
          }}
        />

        <AnimatePresence>
          <div className="absolute bottom-6 left-1/2 -translate-x-1/2 flex items-center justify-center gap-2 select-none">
            <motion.div
              key="install-button"
              whileHover={{
                width: "140px",
                transition: { duration: 0.2 },
              }}
              transition={{ duration: 0.2 }}
              onClick={() => {
                alert("Coming soon...");
              }}
              id="install-button"
              className="backdrop-blur-sm py-1 px-6 rounded-full bg-blue-500/40 border-2 border-blue-400 cursor-wrap-around flex items-center justify-center gap-2 text-md"
            >
              <Download size={16} />
              Install
            </motion.div>
            <motion.div
              key="source-button"
              whileHover={{
                width: "140px",
                transition: { duration: 0.2 },
              }}
              transition={{ duration: 0.2 }}
              onClick={() => {
                setSourceClicked(true);
                location.href = "https://github.com/lu2000luk/S4?ref=s4site";
              }}
              id="source-button"
              className="backdrop-blur-sm py-1 px-6 rounded-full bg-stone-500/40 border-2 border-stone-400 cursor-wrap-around flex items-center justify-center gap-2 text-md"
            >
              {!sourceClicked && (
                <>
                  <Github size={16} />
                  {"Source"}
                </>
              )}
              {sourceClicked && (
                <>
                  <Loading />
                  {"Source"}
                </>
              )}
            </motion.div>
          </div>
        </AnimatePresence>
      </div>
    </>
  );
}
