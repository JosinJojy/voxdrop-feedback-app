"use client";

import { motion } from "framer-motion";

const AnimatedCard = ({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) => {
  return (
    <motion.div
      initial={{ opacity: 0 }} 
      whileInView={{ opacity: 1 }} 
      transition={{ duration: 0.2, ease: "easeOut" }}
      viewport={{ once: true, amount: 0.4 }}
      className={className? className : ""}
    >
      {children}
    </motion.div>
  );
};

export default AnimatedCard;
