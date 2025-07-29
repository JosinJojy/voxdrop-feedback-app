export const getCategoryColor = (category: string) => {
  switch (category) {
    case "positive":
      return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300 border-green-200 dark:border-green-800";
    case "improvement":
      return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300 border-yellow-200 dark:border-yellow-800";
    case "concern":
      return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300 border-red-200 dark:border-red-800";
    default:
      return "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300 border-gray-200 dark:border-gray-800";
  }
};

export const getCategoryIcon = (category: string) => {
  switch (category) {
    case "positive":
      return "🎉";
    case "improvement":
      return "💡";
    case "concern":
      return "⚠️";
    default:
      return "💬";
  }
};

export const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};

export const getCategoryGradient = (category: string) => {
  switch (category) {
    case "positive":
      return "from-green-500/20 to-emerald-500/20";
    case "improvement":
      return "from-yellow-500/20 to-orange-500/20";
    case "concern":
      return "from-red-500/20 to-pink-500/20";
    default:
      return "from-blue-500/20 to-purple-500/20";
  }
};

export const FeedbackType = [
  {
    value: "positive",
    label: "Positive Feedback",
    desc: "Something that's working well",
  },
  {
    value: "improvement",
    label: "Suggestion for Improvement",
    desc: "Ideas to make things better",
  },
  {
    value: "concern",
    label: "Concern or Issue",
    desc: "Something that needs attention",
  },
  {
    value: "general",
    label: "General Feedback",
    desc: "Other thoughts or comments",
  },
];

export const initialFeedbackFromDeveloper = `👋 Hey there!
Welcome aboard — I’m thrilled to have you here! 🎉

This is your personal space to share thoughts, ask questions, or just speak your mind.

I built this for you — so feel free to explore, experiment, and make it yours.

Enjoy!
— The Dev 💻💙`;
