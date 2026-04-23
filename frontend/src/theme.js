import { createTheme } from '@mui/material/styles';

const { palette } = createTheme();

const theme = createTheme({
  palette: {
    primary:    { main: '#3949ab', dark: '#1a237e' },
    secondary:  { main: '#7c4dff' },
    success:    { main: '#2e7d32' },
    warning:    { main: '#e65100' },
    background: { default: '#f5f6fa' },
    surface: palette.augmentColor({
      color: { main: '#1e293b', light: '#334155' },
      name: 'surface',
    }),
  },
  shape: { borderRadius: 8 },
  typography: {
    fontFamily: '"Inter", "Roboto", sans-serif',
  },
  components: {
    MuiButton: {
      styleOverrides: {
        sizeLarge: ({ theme: t }) => ({
          fontWeight: t.typography.fontWeightBold,
          fontSize: t.typography.body1.fontSize,
          paddingTop: t.spacing(1.5),
          paddingBottom: t.spacing(1.5),
        }),
      },
    },
  },
});

export default theme;
